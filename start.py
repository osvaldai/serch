import time
import sys
from bit import Key

key_count = 100000
baseName = 'D:\\88\\base.txt'
profit = 'D:\\88\\out.txt'

print('Чтение базы...', flush=True, end='')

start = time.time()
f = open(baseName, 'r')
t = set(f.read().split('\n'))
end = time.time()
f.close()
print('sec:', end - start, flush=True)
y = 0

print('start generation...', flush=True)
while True:
    # генерация кошельков
    y += 1
    print('generation ', y, flush=True)
    mass = {}
    for _ in range(key_count):
        k = Key()
        mass[k.address] = k.to_wif()
        mass[k.segwit_address] = k.to_wif()
    # проверка сгенерированного

    print('проверка ...', flush=True)
    for key in mass:
        if key in t:
            with open(profit, 'a') as out:
                out.write('{},{}\n'.format(key, mass[key]))
                print('что-то нашли ...', flush=True)
