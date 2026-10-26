#!/usr/bin/env python3
# Generates structurally-valid minimal ELF seed files for disassemble_fuzzer
# (bloaty's --disassemble path, src/disassemble.cc).
#
# Each seed is a minimal ET_EXEC with:
#   - one PT_LOAD program header covering a .text section at vaddr 0x400000,
#   - a .symtab (with linked .strtab) containing one STB_GLOBAL/STT_FUNC
#     symbol named "f" with a non-zero size, so the harness's symbol lookup
#     succeeds and bloaty::DisassembleFunction disassembles the code bytes,
#   - an e_machine that maps to a capstone architecture, so several
#     architectures' decoders are reachable from the corpus.
#
# The harness input is [name_len][name][elf]; seeds use the 1-byte name "f".
# Run from the repo root and commit the regenerated files:
#
#   python3 tests/testdata/disassemble_corpus/gen_disassemble_seeds.py

import os
import struct

OUT = os.path.dirname(os.path.abspath(__file__))

VADDR = 0x400000
TEXT_OFFSET = 0x100

# Short, arch-plausible instruction sequences (need not be valid programs).
CODE = {
    "x86_64": bytes.fromhex(
        "554889e54883ec10488b450083c001488945f8e8100000004883c4105dc3"
        "0f1f440000660fefc0f30f1efa"),
    "i386": bytes.fromhex(
        "5589e583ec108b450883c0018945f8e80a00000083c4105dc3"
        "906690f30f1efa"),
    "arm": bytes.fromhex(
        "e92d4800e24dd004e3a00000e2850004e1a01002eb000001"
        "e24bd004e8bd8000e12fff1e"),
    "aarch64": bytes.fromhex(
        "a9bf7bfd910003fda90153f8b000005911000080540003401406a0fa"
        "a8c17bfdd65f03c0"),
    "mips": bytes.fromhex(
        "27bdfff8afbf0014afbe0010e8a20000e8c3000410600018"
        "8fbf00148fbe000c03e00008"),
    "ppc": bytes.fromhex(
        "7c0802a69421fff07c6000a57c6300d0400200487c6300d0"
        "7c60012e4e80002060000000"),
    "sparc": bytes.fromhex(
        "9de3bf5090100001b006a1060d01c060f9de3bf5090100001"
        "81c00000d81c3e008"),
}


def ehdr(elf_class, ei_data, e_type, e_machine, e_entry, e_phoff, e_shoff,
         e_phnum, e_shnum, e_shstrndx):
    en = "<" if ei_data == 1 else ">"
    ident = b"\x7fELF" + bytes([elf_class, ei_data, 1]) + b"\x00" * 9
    if elf_class == 2:  # ELF64
        return ident + struct.pack(
            en + "HHIQQQIHHHHHH", e_type, e_machine, 1, e_entry, e_phoff,
            e_shoff, 0, 64, 56, e_phnum, 64, e_shnum, e_shstrndx)
    return ident + struct.pack(
        en + "HHIIIIIHHHHHH", e_type, e_machine, 1, e_entry, e_phoff, e_shoff,
        0, 52, 32, e_phnum, 40, e_shnum, e_shstrndx)


def phdr(elf_class, ei_data, offset, filesz):
    en = "<" if ei_data == 1 else ">"
    if elf_class == 2:  # ELF64: type, flags, offset, vaddr, paddr, filesz, memsz, align
        return struct.pack(en + "IIQQQQQQ", 1, 5, offset, VADDR, VADDR, filesz,
                           filesz, 0x1000)
    # ELF32: type, offset, vaddr, paddr, filesz, memsz, flags, align
    return struct.pack(en + "IIIIIIII", 1, offset, VADDR, VADDR, filesz,
                       filesz, 5, 0x1000)


def sym(elf_class, ei_data, name_off, value, size):
    en = "<" if ei_data == 1 else ">"
    st_info = (1 << 4) | 2  # STB_GLOBAL | STT_FUNC
    if elf_class == 2:
        return struct.pack(en + "IBBHQQ", name_off, st_info, 0, 1, value, size)
    return struct.pack(en + "IIIBBH", name_off, value, size, st_info, 0, 1)


def shdr(elf_class, ei_data, name, sh_type, flags, addr, offset, size, link,
         entsize, align=1):
    en = "<" if ei_data == 1 else ">"
    if elf_class == 2:
        return struct.pack(en + "IIQQQQIIQQ", name, sh_type, flags, addr,
                           offset, size, link, 0, align, entsize)
    return struct.pack(en + "IIIIIIIIII", name, sh_type, flags, addr, offset,
                       size, link, 0, align, entsize)


def build(arch, elf_class, ei_data, e_machine):
    code = CODE[arch]
    shstrtab = b"\x00.text\x00.shstrtab\x00.symtab\x00.strtab\x00"
    strtab = b"\x00f\x00"
    syms = sym(elf_class, ei_data, 0, 0, 0) + sym(elf_class, ei_data, 1, VADDR, len(code))

    off = TEXT_OFFSET + len(code)
    def align(n, a=8):
        nonlocal off
        off = (off + a - 1) & ~(a - 1)
        return off

    shstrtab_off = align(8); off = shstrtab_off + len(shstrtab)
    strtab_off = align(1)
    off = strtab_off + len(strtab)
    symtab_off = align(8); off = symtab_off + len(syms)
    shoff = align(8)

    e = ehdr(elf_class, ei_data, 2, e_machine, VADDR,
             64 if elf_class == 2 else 52, shoff, 1, 5, 2)
    p = phdr(elf_class, ei_data, TEXT_OFFSET, len(code))
    out = bytearray(e + p)
    out += b"\x00" * (TEXT_OFFSET - len(out))
    out += code
    out += b"\x00" * (shstrtab_off - len(out)); out += shstrtab
    out += b"\x00" * (strtab_off - len(out)); out += strtab
    out += b"\x00" * (symtab_off - len(out)); out += syms
    out += b"\x00" * (shoff - len(out))

    shentsize = 64 if elf_class == 2 else 40
    sym_entsize = 24 if elf_class == 2 else 16
    # Section-name offsets in shstrtab:
    #   \0 .text \0 .shstrtab \0 .symtab \0 .strtab \0
    #   0  1        7          17        25
    # [0] NULL, [1] .text, [2] .shstrtab, [3] .symtab, [4] .strtab
    out += shdr(elf_class, ei_data, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    out += shdr(elf_class, ei_data, 1, 1, 0x6, VADDR, TEXT_OFFSET, len(code), 0, 0, 16)
    out += shdr(elf_class, ei_data, 7, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1)
    out += shdr(elf_class, ei_data, 17, 2, 0, 0, symtab_off, len(syms), 4, sym_entsize, 8)
    out += shdr(elf_class, ei_data, 25, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1)
    assert len(out) == shoff + 5 * shentsize, (len(out), shoff)
    return b"\x01f" + bytes(out)  # [name_len=1]["f"][elf]


ARCHS = {
    "x86_64": (2, 1, 62),   # ELF64 LE, EM_X86_64
    "i386": (1, 1, 3),      # ELF32 LE, EM_386
    "arm": (1, 1, 40),      # ELF32 LE, EM_ARM
    "aarch64": (2, 1, 183),  # ELF64 LE, EM_AARCH64
    "mips": (1, 2, 8),      # ELF32 BE, EM_MIPS
    "ppc": (1, 2, 20),      # ELF32 BE, EM_PPC
    "sparc": (1, 2, 2),     # ELF32 BE, EM_SPARC
}


def main():
    for arch, (elf_class, ei_data, e_machine) in ARCHS.items():
        data = build(arch, elf_class, ei_data, e_machine)
        name = "%02d-%s.elf" % (sorted(ARCHS).index(arch) + 1, arch)
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
        print("wrote %s (%d bytes)" % (name, len(data)))


if __name__ == "__main__":
    main()
