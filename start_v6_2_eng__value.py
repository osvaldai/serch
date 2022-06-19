# -*- coding cp-1252 -*-
# gen keys from the range between startval and startval+key_count
import time
# import sys
from bit import Key
import os
from bit.format import bytes_to_wif
from multiprocessing import Lock, Process, cpu_count


def get_babulesy(numpotok, k_count, profit_file, base_file, lock, beginRangeValue, lenRange):
    pid = os.getpid()
    lock.acquire()
    print("process PID", pid, numpotok, ' read base...', flush=True)
    start = time.time()
    t = frozenset([line.rstrip('\n') for line in open(base_file, 'r',
                                                      encoding="cp1252")])  # first we create a list, and then we convert it to a set. The set generator is not used because the script load time increases
    print('time read:', time.time() - start, flush=True)
    del start
    lock.release()
    y = 0
    print("process PID", pid, numpotok, 'start generation...', flush=True)

    currentValue = beginRangeValue
    endRangeValueTmp = currentValue + k_count

    while True:
        # key generation unit
        y += 1
        print("process PID", pid, numpotok, 'generation ', y, flush=True)
        mass = {}
        begVal = currentValue
        while currentValue < endRangeValueTmp:
            k = Key().from_int(currentValue)  # kompressed key
            mass[k.address] = k.to_wif()  # address made from compressed key
            # mass[k.segwit_address]=k.to_wif() #segwit address made from compressed key
            wif = bytes_to_wif(k.to_bytes(), compressed=False)  # uncompressed key
            k1 = Key(wif)  # address made from uncompressed key
            mass[k1.address] = wif
            currentValue += 1
        else:
            print("process PID", pid, numpotok, 'checked', hex(begVal), '-', hex(endRangeValueTmp), flush=True)
            currentValue = endRangeValueTmp + lenRange
            endRangeValueTmp = currentValue + k_count

        # verification of addresses
        print("process PID", pid, numpotok, 'verification ...', y, flush=True)
        vall_set = set(mass.keys())
        c = vall_set.intersection(t)
        if c:
            print("process PID", pid, numpotok, 'BINGO!!! ...', flush=True)
            with open(profit_file, 'a') as out:
                for gg in c:
                    out.write('{},{}\n'.format(gg, mass[gg]))
                out.close()
        del (vall_set)
        del (mass)


if __name__ == '__main__':
    firstSK = 0x8F738ACE2072244741FFA3C01FA89F97AE7AE839BD7966F6B4642979474B0028  # the first value of secret key (HEX format)
    key_count = 100000  # portion of keys

    firstSK = int(firstSK)
    pat = os.path.dirname(__file__)
    baseName = pat + '\\base.txt'
    profit = pat + '\\out1.txt'

    lock = Lock()

    procs = []
    proccount = cpu_count()  # processes count (>0  !!!!!)
    stepRange = (proccount - 1) * key_count

    for u in range(
            proccount):  # launch according to the number of cores, if it does not start, it means there is not enough RAM, you need to reduce the number of threads
        proc = Process(target=get_babulesy,
                       args=(u, key_count, profit, baseName, lock, firstSK + u * key_count, stepRange))
        procs.append(proc)
        proc.start()

    for proc in procs:
        proc.join()
