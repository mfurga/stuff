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

  elf = ELF64(data)
  elf.add_section(bytearray([0x11, 0x22]), "asdf", 0, 0, address=0x123456)
  elf.print()

if __name__ == "__main__":
  main()

