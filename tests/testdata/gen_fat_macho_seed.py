#!/usr/bin/env python3
# Generates a universal (fat) Mach-O seed for fuzz_target's "archs" data
# source sweep: two slices (x86_64, arm64), each a minimal mach_header_64 with
# a single LC_SEGMENT_64 (__TEXT) covering the whole slice.  Mirrors the
# structure exercised by tests/macho/archs.test (yaml2obj docnum=1), compacted.
#
# Run from the repo root and commit the regenerated seed:
#
#   python3 tests/testdata/gen_fat_macho_seed.py

import os
import struct

OUT = "tests/testdata/fuzz_corpus/universal-2arch.macho"


def macho_slice(cputype, cpusubtype, code):
    # mach_header_64 (32 bytes): magic, cputype, cpusubtype, filetype
    # (MH_EXECUTE), ncmds=1, sizeofcmds=72, flags, reserved.
    header = struct.pack("<IiIIIIII", 0xFEEDFACF, cputype, cpusubtype, 2,
                         1, 72, 0x200085, 0)
    # segment_command_64 (72 bytes): cmd=LC_SEGMENT_64, cmdsize, segname[16],
    # vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags.
    seg = struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT",
                      0x100000000, len(header) + 72 + len(code), 0,
                      len(header) + 72 + len(code), 5, 5, 0, 0)
    return header + seg + code


def main():
    # x86_64: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret; nop padding.
    x86_64 = macho_slice(0x01000007, 3, bytes.fromhex("554889E531C05DC3"))
    # arm64: nop; mov x29, sp; ret + padding.
    arm64 = macho_slice(0x0100000C, 0, bytes.fromhex("1F2003D5FD7BBFA9FD7BC1A8C0035FD6"))

    align = 0x100
    off0 = 0x100
    off1 = (off0 + len(x86_64) + align - 1) & ~(align - 1)

    fat = struct.pack(">II", 0xCAFEBABE, 2)
    fat += struct.pack(">IIIII", 0x01000007, 3, off0, len(x86_64), 12)
    fat += struct.pack(">IIIII", 0x0100000C, 0, off1, len(arm64), 12)

    out = bytearray(fat)
    out += b"\x00" * (off0 - len(out)); out += x86_64
    out += b"\x00" * (off1 - len(out)); out += arm64

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(out)
    print("wrote %s (%d bytes; slices at 0x%x/0x%x)"
          % (OUT, len(out), off0, off1))


if __name__ == "__main__":
    main()
