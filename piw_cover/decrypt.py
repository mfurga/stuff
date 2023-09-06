#!/usr/bin/env python3

d = open("cover.txt", "r").read().splitlines()
s = "".join(d)
s = s[:-3]
b = bytearray.fromhex(s)

r = bytearray()

for i in range(0, 2 * 89, 2):
  ax = (b[i + 1] << 8) | b[i]
  ax ^= 0x5245
  r.append(ax & 0xff)
  r.append(ax >> 8)

print(r)
open("res.bin", "wb").write(r)

