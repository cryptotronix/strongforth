#!/usr/bin/env python

dictionary = None
with open("zforth.save", "rb") as f:
    dictionary = f.read()

dict_bytestr = dictionary.hex()

dict_bytes = ["0x" + dict_bytestr[i:i+2] for i in range(0, len(dict_bytestr), 2)]

print("{", end="")
i = 0
for byte in dict_bytes:
    if i == 16:
        print("\n ", end="")
        i = 0
    print(byte, end=", ")
    i = i + 1
print("}",)
