#!/usr/bin/env python3

import sys
import struct
from pprint import pprint

def elf_section_name(str):
  return str[:str.find(b"\x00")].decode("utf-8")

class Header:
  # ELF types
  ET_NONE = 0
  ET_REL = 1
  ET_EXEC = 2
  ET_DYN = 3
  ET_CORE = 4

  def __init__(self):
    self.ident = b""
    self.type = None
    self.machine = None
    self.version = None
    self.entry = None
    self.phoff = None
    self.shoff = None
    self.flags = None
    self.ehsize = None
    self.phentsize = None
    self.phnum = None
    self.shentsize = None
    self.shnum = None
    self.shstrndx = None

  @classmethod
  def load_from_bytes(cls, data: bytes):
    header = cls()
    header.unpack(data)
    return header

  def unpack(self, data: bytes) -> None:
    (
      *self.ident,
      self.type,
      self.machine,
      self.version,
      self.entry,
      self.phoff,
      self.shoff,
      self.flags,
      self.ehsize,
      self.phentsize,
      self.phnum,
      self.shentsize,
      self.shnum,
      self.shstrndx
    ) = struct.unpack("<16BHHI3QI6H", data)

  def pack(self) -> bytes:
    return struct.pack("<16BHHI3QI6H",
      *self.ident,
      self.type,
      self.machine,
      self.version,
      self.entry,
      self.phoff,
      self.shoff,
      self.flags,
      self.ehsize,
      self.phentsize,
      self.phnum,
      self.shentsize,
      self.shnum,
      self.shstrndx)

  @staticmethod
  def type_str(type: int) -> str:
    ET_STR = {
      Header.ET_NONE: "None",
      Header.ET_REL: "Relocatable object",
      Header.ET_EXEC: "Executable",
      Header.ET_DYN: "Shared object",
      Header.ET_CORE: "Core"
    }
    if type in ET_STR:
      return ET_STR[type]
    return "UNKNOWN"

  def __str__(self) -> str:
    s = []
    s.append("{:<34}: {} ({})".format("Type", self.type_str(self.type), self.type))
    s.append("{:<34}: {}".format("Machine", self.machine))
    s.append("{:<34}: {}".format("Version", self.version))
    s.append("{:<34}: 0x{:x}".format("Entry point", self.entry))
    s.append("{:<34}: {}".format("Program header offset", self.shoff))
    s.append("{:<34}: {}".format("Section header offset", self.phoff))
    s.append("{:<34}: {}".format("Flags", self.flags))
    s.append("{:<34}: {}".format("Header size", self.ehsize))
    s.append("{:<34}: {}".format("Size of program header entry", self.phentsize))
    s.append("{:<34}: {}".format("Number of program header entries", self.phnum))
    s.append("{:<34}: {}".format("Size of section header entry", self.shentsize))
    s.append("{:<34}: {}".format("Number of section header entries", self.shnum))
    s.append("{:<34}: {}".format("Section name string table index", self.shstrndx))
    return "\n".join(s)

class Segment:
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

  # Program header flags
  PF_X = 0x1
  PF_W = 0x2
  PF_R = 0x4

  def __init__(self) -> None:
    self.type = None
    self.flags = None
    self.offset = None,
    self.vaddr = None
    self.paddr = None
    self.filesz = None
    self.memsz = None
    self.align = None

    self.sections = []

  @classmethod
  def load_from_bytes(cls, data: bytes):
    segment = cls()
    segment.unpack(data)
    return segment

  def unpack(self, data: bytes) -> None:
    (
      self.type,
      self.flags,
      self.offset,
      self.vaddr,
      self.paddr,
      self.filesz,
      self.memsz,
      self.align,
    ) = struct.unpack("<II6Q", data)

  def pack(self) -> bytes:
    return struct.pack("<II6Q",
      self.type,
      self.flags,
      self.offset,
      self.vaddr,
      self.paddr,
      self.filesz,
      self.memsz,
      self.align)

  @staticmethod
  def type_str(type: int) -> str:
    PT_STR = {
      Segment.PT_NULL: "NULL",
      Segment.PT_LOAD: "LOAD",
      Segment.PT_DYNAMIC: "DYNAMIC",
      Segment.PT_INTERP: "INTERP",
      Segment.PT_NOTE: "NOTE",
      Segment.PT_SHLIB: "SHLIB",
      Segment.PT_PHDR: "PHDR"
    }
    if type in PT_STR:
      return PT_STR[type]
    if Segment.PT_LOOS <= type <= Segment.PT_HIOS:
      return "OS"
    if Segment.PT_LOPROC <= type <= Segment.PT_HIPROC:
      return "PROC"
    return "UNKNOWN"

  @staticmethod
  def flags_str(flags: int) -> str:
    return "{}{}{}".format(
      "R" if flags & Segment.PF_R else " ",
      "W" if flags & Segment.PF_W else " ",
      "X" if flags & Segment.PF_X else " "
    )

  def __str__(self) -> str:
    return "{:<12}{:<8}{:<8}0x{:<10x}0x{:<10x}{:<8}{:<8}0x{:<6x}".format(
      Segment.type_str(self.type),
      Segment.flags_str(self.flags),
      self.offset,
      self.vaddr,
      self.paddr,
      self.filesz,
      self.memsz,
      self.align
    )

class Section:
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

  # Section flags
  SHF_WRITE = 0x1
  SHF_ALLOC = 0x2
  SHF_EXECINSTR = 0x4

  def __init__(self) -> None:
    self.name = 0
    self.type = 0
    self.flags = 0
    self.addr = 0
    self.offset = 0
    self.size = 0
    self.link = 0
    self.info = 0
    self.addralign = 1
    self.entsize = 0

    self.content = bytes()

  @classmethod
  def load_from_bytes(cls, sh: bytes, data: bytes):
    section = cls()
    section.unpack(sh)

    if section.type != Section.SHT_NOBITS:
      start = section.offset
      end = start + section.size
      section.content = data[start:end]
    return section

  def unpack(self, data: bytes) -> None:
    (
      self.name,
      self.type,
      self.flags,
      self.addr,
      self.offset,
      self.size,
      self.link,
      self.info,
      self.addralign,
      self.entsize
    ) = struct.unpack("<II4QIIQQ", data)

  def pack(self) -> bytes:
    return struct.pack("<II4QIIQQ",
      self.name,
      self.type,
      self.flags,
      self.addr,
      self.offset,
      self.size,
      self.link,
      self.info,
      self.addralign,
      self.entsize)

  @staticmethod
  def type_str(type: int) -> str:
    SHT_STR = {
      Section.SHT_NULL: "NULL",
      Section.SHT_PROGBITS: "PROGBITS",
      Section.SHT_SYMTAB: "SYMTAB",
      Section.SHT_STRTAB: "STRTAB",
      Section.SHT_RELA: "RELA",
      Section.SHT_HASH: "HASH",
      Section.SHT_DYNAMIC: "DYNAMIC",
      Section.SHT_NOTE: "NOTE",
      Section.SHT_NOBITS: "NOBITS",
      Section.SHT_REL: "REL",
      Section.SHT_SHLIB: "SHLIB",
      Section.SHT_DYNSYM: "DYNSYM",
      Section.SHT_INIT_ARRAY: "INIT ARRAY",
      Section.SHT_FINI_ARRAY: "FINI ARRAY"
    }
    if type in SHT_STR:
      return SHT_STR[type]
    if Section.SHT_LOOS <= type <= Section.SHT_HIOS:
      return "OS"
    if Section.SHT_LOPROC <= type <= Section.SHT_HIPROC:
      return "PROC"
    return "UNKNOWN"

  @staticmethod
  def flags_str(flags: int) -> str:
    return "{}{}{}".format(
      "A" if flags & Section.SHF_ALLOC else " ",
      "W" if flags & Section.SHF_WRITE else " ",
      "E" if flags & Section.SHF_EXECINSTR else " "
    )

  def __str__(self) -> str:
    return "{:<20}{:<12}{:<6}0x{:<8x}{:<8}{:<8}".format(
      self.name,
      self.type_str(self.type),
      self.flags_str(self.flags),
      self.addr,
      self.offset,
      self.size,
    )

class ELF:
  def __init__(self, data: bytearray) -> None:
    self.header: Header = None
    self.segments: list[Segment] = []
    self.sections: list[Section] = []

    self._parse_elf(data)

  def _parse_elf(self, data: bytearray) -> None:
    self.header = Header.load_from_bytes(data[:64])

    for i in range(self.header.phnum):
      start = self.header.phoff + i * self.header.phentsize
      end = start + self.header.phentsize
      self.segments.append(Segment.load_from_bytes(data[start:end]))

    for i in range(self.header.shnum):
      start = self.header.shoff + i * self.header.shentsize
      end = start + self.header.shentsize
      self.sections.append(Section.load_from_bytes(data[start:end], data))

    # Map sections to segments
    for segment in self.segments:
      seg_start = segment.offset
      seg_end = seg_start + segment.filesz - 1
      for i, section in enumerate(self.sections):
        sec_start = section.offset
        sec_end = sec_start + section.size - 1

        if seg_start <= sec_start <= seg_end and \
           seg_start <= sec_end <= seg_end:
           segment.sections.append(i)

  def set_entry_point(self, entry: int) -> None:
    self.header.entry = entry

  def append_section(self, section: Section) -> None:
    section.offset = self.sections[-1].offset + self.sections[-1].size

    padding = 0
    if section.offset % section.addralign != 0:
      padding = section.addralign - (section.offset % section.addralign)
      section.offset += padding

    self.sections.append(section)
    self.header.shnum += 1
    self.header.shoff += section.size + padding

  def data(self) -> bytes:
    b = b""
    b += self.header.pack()

    b = b.ljust(self.header.phoff, b"\x00")
    for i in range(self.header.phnum):
      b += self.segments[i].pack()

    for i in range(self.header.shnum):
      b = b.ljust(self.sections[i].offset, b"\x00")
      b += self.sections[i].content

    b = b.ljust(self.header.shoff, b"\x00")
    for i in range(self.header.shnum):
      section = self.sections[i]
      b += section.pack()

    return b

  def __str__(self):
    s = []
    s.append(str(self.header))
    s.append("\nSegments:")
    s.append("{:<12}{:<8}{:<8}{:<12}{:<12}{:<8}{:<8}{:<8}".format(
      "Type", "Flags", "Offset", "Vaddr", "Paddr", "Filesz", "Memsz", "Align"))
    for segment in self.segments:
      s.append(str(segment))
    s.append("\nSections:")
    s.append("{:<20}{:<12}{:<6}{:<10}{:<8}{:<8}".format(
      "Name", "Type", "Flags", "Address", "Offset", "Size"))
    for section in self.sections:
      s.append(str(section))
    return "\n".join(s)

