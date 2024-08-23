# from module import fun_a

# fun_a()

import module
print(module.counter)

from module2 import suml, prodl

zeroes = [0 for i in range(5)]
ones = [1 for i in range(5)]
print(suml(zeroes))
print(prodl(ones))

