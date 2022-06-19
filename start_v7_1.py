#!/usr/bin/env python3
import time
import collections
import hashlib
import random
import codecs
import os
from multiprocessing import Lock, Process, cpu_count, Queue, Pipe

ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58decode(ins: str) -> int:
    """Converts a Base-58 encoded integer, as string, back to a number. """
    multi: int = 1
    decoded: int = 0
    alpha_cnt: int = len(ALPHA)
    for char in ins[::-1]:
        decoded += multi * ALPHA.index(char)
        multi *= alpha_cnt
    return decoded


EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################
def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')
    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)
    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    gcd, x, y = old_r, old_s, old_t
    assert gcd == 1
    assert (k * x) % p == 1
    return x % p


# Functions that work on curve points #########################################
def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    # assert is_on_curve(point)
    if point is None:
        # -0 = 0
        return None
    x, y = point
    result = (x, -y % curve.p)
    # assert is_on_curve(result)
    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    # assert is_on_curve(point1)
    # assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    # assert is_on_curve(result)
    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    # assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    # assert is_on_curve(result)
    return result


def getHashFromAdress(adr: str):
    # из строки адреса получаем хеш публичного ключа
    decoded = "{:x}".format(b58decode(adr))
    hashPublicKey = decoded[:-8].zfill(40)
    return hashPublicKey


def loadBase(baseName: str):
    """Загрузка хешей публичных ключей из базы адресов"""
    t = set()
    f = open(baseName)
    for line in f:
        if line[0] == '1':
            hashTmp = bytes.fromhex(getHashFromAdress(line.rstrip('\n')))
            t.add(hashTmp)
    return t


def genHashes(kc, q):
    while True:
        private_key = random.randrange(1, curve.n)

        public_key = scalar_mult(private_key, curve.g)
        hashesGen = set()
        for _ in range(kc):  # create hashes of public keys
            # compressed Pub Key
            prefix = '02' if public_key[1] % 2 == 0 else '03'
            public_keyX = '{:x}'.format(public_key[0])
            public_keyY = '{:x}'.format(public_key[1])
            if len(public_keyX) % 2 > 0:
                public_keyX = '0' + public_keyX
            if len(public_keyY) % 2 > 0:
                public_keyY = '0' + public_keyY
            pK = '{}{}'.format(prefix, public_keyX)
            ripemd160 = hashlib.new('ripemd160', hashlib.sha256(codecs.decode(pK, 'hex')).digest())
            hashesGen.add(ripemd160.digest())
            # UNcompressed Pub Key
            pK = '04{}{}'.format(public_keyX, public_keyY)
            ripemd160 = hashlib.new('ripemd160', hashlib.sha256(codecs.decode(pK, 'hex')).digest())
            hashesGen.add(ripemd160.digest())
            public_key = point_add(public_key, curve.g)
        q.put([hex(private_key), hashesGen])


waitGen = True


def checkGen(baseName, q, prof, conn, key_count):
    print('Load base ... ', end='')
    start = time.time()
    base = loadBase(baseName)
    print('time read:', time.time() - start, flush=True)
    del start
    conn.send(False)

    while True:
        if q.empty():
            time.sleep(3)
        else:
            setTmp = q.get()
            print('Checking. Starting PrivKey {}'.format(setTmp[0]))
            c = base.intersection(setTmp[1])
            if c:
                print('BINGO!!! ...', setTmp[0], key_count, flush=True)
                with open(prof, 'a+') as out:
                    out.write('{},{}\n'.format(str(setTmp[0]), str(key_count)))
                    out.close()


if __name__ == '__main__':
    key_count = 100000
    pat = os.path.dirname(os.path.abspath(__file__)) + "\\"
    baseName = pat + 'base.txt'
    profit = pat + 'out.txt'
    qout = Queue()
    parent_conn, child_conn = Pipe()

    procs = []
    proc = Process(target=checkGen, args=(baseName, qout, profit, child_conn, key_count))
    procs.append(proc)
    proc.start()
    while parent_conn.recv():
        time.sleep(5)

    print('start generation')
    multiprocessingCount = cpu_count()
    for u in range(
            multiprocessingCount):  # launch according to the number of cores, if it does not start, it means there is not enough RAM, you need to reduce the number of threads
        proc = Process(target=genHashes, args=(key_count, qout))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()
