#!/usr/bin/env python3

import sys
import struct
from pprint import pprint

from elf64 import *

def main():
  if len(sys.argv) != 2:
    print("%s <ELF prog>" % sys.argv[0])
    sys.exit(1)

  with open(sys.argv[1], "rb") as f:
    data = f.read()

  elf = ELF(data)

  address = 0x80000000

  content = bytearray([0xcc] * 512)
  section = Section()
  section.type = Section.SHT_PROGBITS
  section.size = len(content)
  section.content = content
  section.addralign = 16
  section.addr = address

  # segment = Segment()
  # segment.type = Segment.PT_NULL
  # segment.flags = Segment.PF_R | Segment.PF_X
  # segment.offset = 0
  # segment.vaddr = 0x8000_0000
  # segment.paddr = 0
  # segment.filesz = 512
  # segment.memsz = 512
  # segment.align = 16

  # elf.append_segment(segment)
  elf.append_section(section)
  # elf.set_entry_point(address)

  with open("%s.packed" % sys.argv[1], "wb") as f:
    f.write(elf.data())

if __name__ == "__main__":
  main()

