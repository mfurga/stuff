#!/usr/bin/env python3

import sys
import struct
from pprint import pprint

ELF_MAGIC = b"\x7fELF"

EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8
EI_NIDENT = 16

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1
ELFDATA2MSB = 2

ELFOSABI_SYSV = 0
ELFOSABI_HPUX = 1
ELFOSABI_STANDALONE = 255

def elf_half(data, off):
  return struct.unpack("<H", data[off:off + 2])[0]

def elf_word(data, off):
  return struct.unpack("<I", data[off:off + 4])[0]

def elf_xword(data, off):
  return struct.unpack("<Q", data[off:off + 8])[0]

def elf_addr(data, off):
  return elf_xword(data, off)

def elf_off(data, off):
  return elf_xword(data, off)

def print_elf(data, hdr, shdrs):
  e_shstrndx = hdr["e_shstrndx"]

  assert(e_shstrndx < len(shdrs))

  shdr_str = shdrs[e_shstrndx]
  s_str_offset = shdr_str["sh_offset"]
  s_str_size = shdr_str["sh_size"]

  for shdr in shdrs:
    sh_name = shdr["sh_name"]
    #print(data[s_str_offset + sh_name:])

def error(msg):
  print(msg)
  sys.exit(1)

def parse_elf_header(hd):
  hdr = {}

  e_ident = hd[0:15 + 1]

  # Parser supports only little-endian ELF64 binaries
  assert(e_ident[EI_CLASS] == ELFCLASS64)
  assert(e_ident[EI_DATA] == ELFDATA2LSB)

  hdr["e_ident"] = e_ident
  hdr["e_type"] = elf_half(hd, 16)
  hdr["e_machine"] = elf_half(hd, 18)
  hdr["e_version"] = elf_word(hd, 20)
  hdr["e_entry"] = elf_addr(hd, 24)
  hdr["e_phoff"] = elf_off(hd, 32)
  hdr["e_shoff"] = elf_off(hd, 40)
  hdr["e_flags"] = elf_word(hd, 48)
  hdr["e_ehsize"] = elf_half(hd, 52)
  hdr["e_phentsize"] = elf_half(hd, 54)
  hdr["e_phnum"] = elf_half(hd, 56)
  hdr["e_shentsize"] = elf_half(hd, 58)
  hdr["e_shnum"] = elf_half(hd, 60)
  hdr["e_shstrndx"] = elf_half(hd, 62)

  #pprint(hdr)

  return hdr

def parse_elf_section_header(sh):
  shdr = {}

  shdr["sh_name"] = elf_word(sh, 0)
  shdr["sh_type"] = elf_word(sh, 4)
  shdr["sh_flags"] = elf_xword(sh, 8)
  shdr["sh_addr"] = elf_addr(sh, 16)
  shdr["sh_offset"] = elf_off(sh, 24)
  shdr["sh_size"] = elf_xword(sh, 32)
  shdr["sh_link"] = elf_word(sh, 40)
  shdr["sh_info"] = elf_word(sh, 44)
  shdr["sh_addralign"] = elf_xword(sh, 48)
  shdr["sh_entsize"] = elf_xword(sh, 56)

  return shdr

def parse_elf(data):
  hdr = parse_elf_header(data[:64])

  e_ident = hdr["e_ident"]
  e_shoff = hdr["e_shoff"]
  e_shnum = hdr["e_shnum"]
  e_shentsize = hdr["e_shentsize"]

  shdrs = []
  for i in range(e_shnum):
    shdrs.append(parse_elf_section_header(
      data[e_shoff + i * e_shentsize:]))

  print_elf(data, hdr, shdrs)

  if e_ident[:4] != ELF_MAGIC:
    error("No ELF file")

  if e_ident[EI_CLASS] != ELFCLASS64:
    error("Packer supports only ELF64 binaries")

  if e_ident[EI_DATA] != ELFDATA2LSB:
    error("Packer supports only little-endian encoding")

  if e_ident[EI_OSABI] != ELFOSABI_SYSV:
    error("Packer supports only SYS-V ABI")

  if e_ident[EI_ABIVERSION] != 0:
    error("Bad ABI version")

def main():
  if len(sys.argv) != 2:
    print("%s <ELF prog>" % sys.argv[0])
    sys.exit(1)

  with open(sys.argv[1], "rb") as f:
    prog = f.read()

  parse_elf(prog)

if __name__ == "__main__":
  main()

