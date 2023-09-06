#!/usr/bin/env python3

from unicorn import *
from unicorn.x86_const import *
import string
import struct

def dw(data):
  return struct.unpack("<L", data)[0]

def crc32(s):
  """
    xor ecx, ecx
  loop:
    mov dl, byte [0x100 + ecx]
    crc32 eax, dl
    inc ecx
    cmp ecx, ebx
    jnz loop
  """
  X86_CODE32 = b'1\xc9\x8a\x91\x00\x01\x00\x00\xf2\x0f8\xf0\xc2A9\xd9u\xf0'

  mu = Uc(UC_ARCH_X86, UC_MODE_32)
  mu.mem_map(0, 2 * 1024 * 1024)
  mu.mem_write(0, X86_CODE32)
  mu.mem_write(0x100, s)

  mu.reg_write(UC_X86_REG_EAX, 0)       # eax = 0
  mu.reg_write(UC_X86_REG_EBX, len(s))  # ebx = len(s)

  mu.emu_start(0, 0 + len(X86_CODE32))
  return mu.reg_read(UC_X86_REG_EAX)

data = open("cover.bin", "rb").read()
checksums = data[0x3d:0x3d + 4 * 23]

s = bytearray()
for i in range(23 - 1, -1, -1):
  ch = checksums[i * 4: i * 4 + 4]
  for c in string.printable:
    t = bytes(c, 'utf-8') + s
    if dw(ch) == crc32(t):
      s = t
      continue

print(s)

