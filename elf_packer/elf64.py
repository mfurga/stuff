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

# Object file types
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4

def et_str(v):
  ET_STR = {
    ET_NONE: "None",
    ET_REL: "Relocatable object",
    ET_EXEC: "Executable",
    ET_DYN: "Shared object",
    ET_CORE: "Core"
  }
  if v in ET_STR:
    return ET_STR[v]
  return "UNKNOWN"

# Program header types
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_LOOS = 0x60000000
PT_HIOS = 0x6FFFFFFF
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7FFFFFFF

def pt_str(v):
  PT_STR = {
    PT_NULL: "NULL",
    PT_LOAD: "LOAD",
    PT_DYNAMIC: "DYNAMIC",
    PT_INTERP: "INTERP",
    PT_NOTE: "NOTE",
    PT_SHLIB: "SHLIB",
    PT_PHDR: "PHDR"
  }
  if v in PT_STR:
    return PT_STR[v]
  if PT_LOOS <= v <= PT_HIOS:
    return "OS"
  if PT_LOPROC <= v <= PT_HIPROC:
    return "PROC"
  return "UNKNOWN"

# Program header flags
PF_X = 1
PF_W = 2
PF_R = 3

def pf_str(v):
  return "{}{}{}".format(
    "R" if v & PF_R else " ",
    "W" if v & PF_W else " ",
    "X" if v & PF_X else " "
  )

# Section types
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14
SHT_FINI_ARRAY = 15
SHT_LOOS = 0x60000000
SHT_HIOS = 0x6FFFFFFF
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7FFFFFFF

def sht_str(v):
  SHT_STR = {
    SHT_NULL: "NULL",
    SHT_PROGBITS: "PROGBITS",
    SHT_SYMTAB: "SYMTAB",
    SHT_STRTAB: "STRTAB",
    SHT_RELA: "RELA",
    SHT_HASH: "HASH",
    SHT_DYNAMIC: "DYNAMIC",
    SHT_NOTE: "NOTE",
    SHT_NOBITS: "NOBITS",
    SHT_REL: "REL",
    SHT_SHLIB: "SHLIB",
    SHT_DYNSYM: "DYNSYM",
    SHT_INIT_ARRAY: "INIT ARRAY",
    SHT_FINI_ARRAY: "FINI ARRAY"
  }
  if v in SHT_STR:
    return SHT_STR[v]
  if SHT_LOOS <= v <= SHT_HIOS:
    return "OS"
  if SHT_LOPROC <= v <= SHT_HIPROC:
    return "PROC"
  return "UNKNOWN"

# Section flags
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

def shf_str(v):
  return "{}{}{}".format(
    "A" if v & SHF_ALLOC else " ",
    "W" if v & SHF_WRITE else " ",
    "E" if v & SHF_EXECINSTR else " "
  )

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

def elf_section_name(str):
  return str[:str.find(b"\x00")].decode("utf-8")

class ELF64:
  def __init__(self, data: bytearray) -> None:
    self._data = data
    self._parse_elf()

  def _parse_elf(self):
    self._hdr = self._parse_elf_header(self._data[:64])

    # Parse program header
    e_phoff = self._hdr["e_phoff"]
    e_phentsize = self._hdr["e_phentsize"]
    e_phnum = self._hdr["e_phnum"]

    self._phdrs = []
    for i in range(e_phnum):
      begin = e_phoff + i * e_phentsize
      end = e_phoff + (i + 1) * e_phentsize

      assert(begin < len(self._data))
      assert(end <= len(self._data))

      self._phdrs.append(
        self._parse_elf_program_header(self._data[begin:end]))

    # Parse section header
    e_shoff = self._hdr["e_shoff"]
    e_shnum = self._hdr["e_shnum"]
    e_shentsize = self._hdr["e_shentsize"]

    self._shdrs = []
    for i in range(e_shnum):
      begin = e_shoff + i * e_shentsize
      end = e_shoff + (i + 1) * e_shentsize

      assert(begin < len(self._data))
      assert(end <= len(self._data))

      self._shdrs.append(
        self._parse_elf_section_header(self._data[begin:end]))

    self._data = bytearray(self._data[self._phdrs_end_offset:e_shoff])

  @property
  def _phdrs_end_offset(self):
    return self._hdr["e_phoff"] + self._hdr["e_phentsize"] * self._hdr["e_phnum"]

  def _parse_elf_header(self, hd):
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

    return hdr

  def _parse_elf_program_header(self, ph):
    phdr = {}

    phdr["p_type"] = elf_word(ph, 0)
    phdr["p_flags"] = elf_word(ph, 4)    
    phdr["p_offset"] = elf_off(ph, 8)
    phdr["p_vaddr"] = elf_off(ph, 16)
    phdr["p_paddr"] = elf_off(ph, 24)
    phdr["p_filesz"] = elf_xword(ph, 32)
    phdr["p_memsz"] = elf_xword(ph, 40)
    phdr["p_align"] = elf_xword(ph, 48)

    if phdr["p_offset"] >= self._phdrs_end_offset:
      # offset relative to beginning of sections / segments
      phdr["p_offset"] -= self._phdrs_end_offset

    return phdr

  def _parse_elf_section_header(self, sh):
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

    if shdr["sh_offset"] >= self._phdrs_end_offset:
      # offset relative to beginning of sections / segments
      shdr["sh_offset"] -= self._phdrs_end_offset

    return shdr

  def add_section(self, data: bytearray, name: str, type: int, flags: int,
                  address: int) -> None:
    shdr = {
      "sh_name": 0,
      "sh_type": type,
      "sh_flags": flags,
      "sh_addr": address,
      "sh_offset": len(self._data),
      "sh_size": len(data),
      "sh_link": 0,
      "sh_info": 0,
      "sh_addralign": 0,
      "sh_entsize": 0
    }

    self._shdrs.append(shdr)
    self._data.extend(data)

  def print(self):
    data = self._data
    hdr = self._hdr
    shdrs = self._shdrs
    phdrs = self._phdrs

    e_shstrndx = hdr["e_shstrndx"]

    assert(e_shstrndx < len(shdrs))

    # print hdr info
    print("ELF info:")
    print("{:<34}: {} ({})".format(
      "Type", et_str(hdr["e_type"]), hdr["e_type"]))
    print("{:<34}: {}".format("Machine", hdr["e_machine"]))
    print("{:<34}: {}".format("Version", hdr["e_version"]))
    print("{:<34}: 0x{:x}".format("Entry point", hdr["e_entry"]))
    print("{:<34}: {}".format("Program header offset", hdr["e_phoff"]))
    print("{:<34}: {}".format("Section header offset", hdr["e_shoff"]))
    print("{:<34}: {}".format("Flags", hdr["e_flags"]))
    print("{:<34}: {}".format("Header size", hdr["e_ehsize"]))
    print("{:<34}: {}".format("Size of program header entry",
      hdr["e_phentsize"]))
    print("{:<34}: {}".format("Number of program header entries",
      hdr["e_phnum"]))
    print("{:<34}: {}".format("Size of section header entry",
      hdr["e_shentsize"]))
    print("{:<34}: {}".format("Number of section header entries",
      hdr["e_shnum"]))
    print("{:<34}: {}".format("Section name string table index",
      hdr["e_shstrndx"]))

    print()
    print("Program header:")
    print("{:<12}{:<8}{:<8}{:<12}{:<12}{:<8}{:<8}{:<8}".format(
      "Type", "Flags", "Offset", "Vaddr", "Paddr", "Filesz", "Memsz", "Align"))

    for phdr in phdrs:
      print("{:<12}{:<8}{:<8}0x{:<10x}0x{:<10x}{:<8}{:<8}0x{:<6x}".format(
        pt_str(phdr["p_type"]),
        pf_str(phdr["p_flags"]),
        phdr["p_offset"],
        phdr["p_vaddr"],
        phdr["p_paddr"],
        phdr["p_filesz"],
        phdr["p_memsz"],
        phdr["p_align"]
      ))

    print()
    print("Sections:")
    print("{:<20}{:<12}{:<6}{:<10}{:<8}{:<8}".format(
      "Name", "Type", "Flags", "Address", "Offset", "Size"))

    shdr_str = shdrs[e_shstrndx]
    s_str_offset = shdr_str["sh_offset"]
    s_str_size = shdr_str["sh_size"]

    for shdr in shdrs:
      str_offset = s_str_offset + shdr["sh_name"]

      print("{:<20}{:<12}{:<6}0x{:<8x}{:<8}{:<8}".format(
        elf_section_name(data[str_offset:]),
        sht_str(shdr["sh_type"]),
        shf_str(shdr["sh_flags"]),
        shdr["sh_addr"],
        shdr["sh_offset"],
        shdr["sh_size"],
      ))

  def get_data(self):
    return self._data
