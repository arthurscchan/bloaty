#!/usr/bin/env python3
# Generates structurally-valid JavaScript source map seeds for
# sourcemap_fuzzer (bloaty's src/source_map.cc parser).
#
# The fuzz harness pairs the map with a fixed 28-byte WebAssembly wrapper, so
# seeds keep segment columns within [0, 28) to match the wrapper layout (the
# fuzzer explores mismatched layouts on its own).  Run from the repo root:
#
#   python3 tests/testdata/sourcemap_corpus/gen_sourcemap_seeds.py
#
# and commit the regenerated files.

import os

OUT = os.path.dirname(os.path.abspath(__file__))


def vlq(value):
    """Base64 VLQ per bloaty's decoder (terminal A-Z/a-f, continuation g-z/0-9/+/)."""
    z = ((-value) << 1) | 1 if value < 0 else value << 1
    out = ""
    while z >= 32:
        d = z & 31
        if d < 20:
            out += chr(ord("g") + d)
        elif d < 30:
            out += chr(ord("0") + d - 20)
        elif d == 30:
            out += "+"
        else:
            out += "/"
        z >>= 5
    if z < 26:
        out += chr(ord("A") + z)
    else:
        out += chr(ord("a") + z - 26)
    return out


def segment(*values):
    return "".join(vlq(v) for v in values)


def mappings(segments):
    return ",".join(segment(*s) for s in segments)


def write(name, text):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(text)


def main():
    # 1: minimal single-source map; absolute first segment at col 0.
    write("01-minimal.map",
          '{"version":3,"sources":["a.js"],"names":[],"mappings":"%s"}'
          % mappings([(0, 0, 0, 0), (1, 0, 0, 1)]))

    # 2: two sources; second segment switches source via delta.
    write("02-multisource.map",
          '{"version":3,"sources":["a.js","b.js"],"names":[],"mappings":"%s"}'
          % mappings([(0, 0, 0, 0), (4, 1, 0, 0), (2, -1, 1, 0), (4, 1, 0, 3)]))

    # 3: columns spanning the 28-byte wasm wrapper (all ranges in [0, 28)).
    write("03-wrapper-layout.map",
          '{"version":3,"sources":["gen.js"],"names":[],"mappings":"%s"}'
          % mappings([(0, 0, 0, 0), (8, 0, 1, 0), (4, 0, 0, 1), (8, 0, 2, 0)]))

    # 4: multi-digit VLQ values (large columns, lines and name indexes).
    write("04-multidigit-vlq.map",
          '{"version":3,"sources":["big.js"],"names":["n0","n1"],"mappings":"%s"}'
          % mappings([(0, 0, 0, 0, 0), (16, 0, 40, 0, 1), (11, 0, -7, 33, 0)]))

    # 5: negative deltas everywhere (col goes down, negative line deltas).
    write("05-negative-deltas.map",
          '{"version":3,"sources":["neg.js","other.js"],"names":[],"mappings":"%s"}'
          % mappings([(0, 0, 5, 5), (3, 1, -2, -4), (1, -1, -1, 9), (5, 0, 0, 0)]))

    # 6: many short segments (unit column deltas keep every range in [0, 28)).
    write("06-many-segments.map",
          '{"version":3,"sources":["many.js"],"names":[],"mappings":"%s"}'
          % mappings([(1, 0, 0, 1) for _ in range(24)]))

    # 7: five-value segments (with names index) throughout.
    write("08-five-value.map",
          '{"version":3,"sources":["five.js","six.js"],"names":["x","y","z"],'
          '"mappings":"%s"}'
          % mappings([(0, 0, 0, 0, 0), (2, 1, 3, 0, 1), (1, -1, 0, 2, 2),
                      (3, 0, 1, 0, 1)]))

    # 8: unknown fields before/after the ones bloaty scans for; FindField must
    # skip them (it scans quoted strings pairwise).
    write("09-extra-fields.map",
          '{"version":3,"file":"out.js","sourceRoot":"/src",'
          '"sources":["r/a.js","r/b.js"],"sourcesContent":[null,null],'
          '"names":[],"mappings":"%s","x-ignore":"1"}'
          % mappings([(0, 0, 0, 0), (6, 1, 2, 0), (4, 0, 0, 4)]))

    # 9: source names that stress the label path (inlines adds ":<line>").
    write("10-inlines-labels.map",
          '{"version":3,"sources":["../deep/path/x.ts","weird name.js",'
          '"u\\nm"], "names":[],"mappings":"%s"}'
          % mappings([(0, 0, 0, 0), (2, 1, 9, 0), (3, 1, 99, 1), (5, 1, 0, 2)]))

    print("wrote %d seeds to %s" % (len(os.listdir(OUT)) - 1, OUT))


if __name__ == "__main__":
    main()
