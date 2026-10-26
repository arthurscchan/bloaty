// Copyright 2026 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Fuzzer for bloaty's JavaScript source map parser (src/source_map.cc).
//
// Threat model: bloaty profiles WebAssembly/JS artifacts together with their
// source maps (`--source-map=<build-id-or-filename>=<map file>`).  When
// profiling binaries obtained from untrusted sources, the source map file
// contents are attacker-controlled, and bloaty parses them with a hand-rolled
// parser (loose JSON field scanning + Base64 VLQ segment decoding).  The
// entire fuzz input is the source map file; the WebAssembly input file is a
// fixed minimal wrapper so the harness exercises exactly the production code
// path: wasm GetBuildId() (sourceMappingURL section) -> source map lookup by
// input file name -> TryOpenSourceMapFile() -> SourceMapObjectFile::
// ProcessFileToSink() for the compileunits and inlines data sources.
//
// The interesting attack surface in the parser includes:
//   - ReadBase64VLQ: unbounded shift accumulation (UB for long digit runs)
//   - ForEachVLQSegment: sources[] indexed by attacker-controlled int32
//     (negative or out-of-range source_file accumulators)
//   - signed overflow in the col/source_line/source_col accumulators
//   - rollup consistency for source maps that do not match the wasm layout
//     (e.g. segment columns beyond the end of the input file)

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "bloaty.h"
#include "bloaty.pb.h"

using std::string_view;

namespace bloaty {
namespace {

constexpr const char* kWasmFilename = "f.wasm";
constexpr const char* kMapFilename = "f.map";

// Minimal valid WebAssembly module: magic + version plus a single custom
// section named "sourceMappingURL" (16 bytes) whose payload is the 1-byte URL
// "x".  This gives the input file a non-empty build id, and the harness
// registers the source map by *input file name* (bloaty falls back to a
// filename-keyed lookup when no source map is keyed by the build id), so the
// URL contents themselves are irrelevant to the code path under test.
const char kWasmWrapper[] = {
    '\x00', 'a',   's',  'm',  '\x01', '\x00', '\x00', '\x00',
    '\x00', '\x13',                                          // custom section id 0, size 19
    '\x10', 's',   'o', 'u', 'r', 'c', 'e', 'M', 'a', 'p', 'p', 'i', 'n', 'g',
    'U',    'R',   'L',                                        // section name (16 bytes)
    '\x01', 'x',                                                // URL: length 1, "x"
};

class StringPieceInputFile : public InputFile {
 public:
  StringPieceInputFile(string_view data, string_view filename)
      : InputFile(filename) {
    data_ = data;
  }

  bool TryOpen(std::string_view /* filename */,
               std::unique_ptr<InputFile>& file) override {
    return false;
  }
};

// Serves the fixed wasm wrapper for the input file and the fuzz data for the
// source map, mirroring how BloatyMain opens both through the file factory.
class WasmAndMapInputFileFactory : public InputFileFactory {
 public:
  WasmAndMapInputFileFactory(string_view wasm_data, string_view map_data)
      : wasm_data_(wasm_data), map_data_(map_data) {}

 private:
  std::unique_ptr<InputFile> OpenFile(
      const std::string& filename) const override {
    string_view data = (filename == kMapFilename) ? map_data_ : wasm_data_;
    return std::unique_ptr<InputFile>(
        new StringPieceInputFile(data, filename));
  }

  string_view wasm_data_;
  string_view map_data_;
};

void RunBloaty(const InputFileFactory& factory) {
  bloaty::RollupOutput output;
  bloaty::Options options;
  std::string error;
  options.add_filename(kWasmFilename);
  // "<input filename>=<map filename>": registered under the input file name
  // so the lookup succeeds for any (non-empty) wasm build id.
  options.add_source_map(std::string(kWasmFilename) + "=" + kMapFilename);
  options.add_data_source("compileunits");
  options.add_data_source("inlines");
  bloaty::BloatyMain(options, factory, &output, &error);
}

}  // namespace
}  // namespace bloaty

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const char* map_data = reinterpret_cast<const char*>(data);
  bloaty::WasmAndMapInputFileFactory factory(
      string_view(bloaty::kWasmWrapper, sizeof(bloaty::kWasmWrapper)),
      string_view(map_data, size));
  bloaty::RunBloaty(factory);
  return 0;
}
