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

// Fuzzer for bloaty's --disassemble path (src/disassemble.cc).
//
// Threat model: bloaty disassembles a named function of a binary supplied on
// the command line (`bloaty --disassemble=<symbol> <file>`).  When profiling
// binaries obtained from untrusted sources, the ELF file contents (header,
// program headers, section table, symbol table, and the code bytes themselves)
// are attacker-controlled, as is the requested symbol name.  The harness
// drives BloatyMain with disassemble_function set and no data sources (the
// disassemble path only runs when no data source is requested).
//
// Input layout: [1-byte name length][symbol name][ELF file].  The fuzzer must
// keep the symbol name in sync with a name in the ELF's .symtab, which the
// seed corpus demonstrates; everything else (code bytes, e_machine, program
// headers, section layout) is free-form attacker data.
//
// The path exercised: Bloaty::DisassembleFunction -> ElfObjectFile::
// GetDisassemblyInfo (base map from PT_LOAD segments, .symtab scan, VM to
// file translation) -> ReadElfArchMode (e_machine -> capstone arch/mode) ->
// bloaty::DisassembleFunction (capstone disassembly + string formatting).
//
// Seed corpus: tests/testdata/disassemble_corpus/*.elf (built by
// gen_disassemble_seeds.py), each a minimal ET_EXEC with a PT_LOAD, a
// .symtab with one STT_FUNC symbol named "f", and arch-plausible code bytes
// (x86-64, i386, ARM, AArch64, MIPS, PPC).

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "bloaty.h"
#include "bloaty.pb.h"

using std::string_view;

namespace bloaty {
namespace {

class StringPieceInputFile : public InputFile {
 public:
  StringPieceInputFile(string_view data)
      : InputFile("fake_StringPieceInputFile_file") {
    data_ = data;
  }

  bool TryOpen(std::string_view /* filename */,
               std::unique_ptr<InputFile>& file) override {
    file.reset(new StringPieceInputFile(data_));
    return true;
  }
};

class StringPieceInputFileFactory : public InputFileFactory {
 public:
  StringPieceInputFileFactory(string_view data) : data_(data) {}

 private:
  string_view data_;
  std::unique_ptr<InputFile> OpenFile(
      const std::string& /* filename */) const override {
    return std::unique_ptr<InputFile>(new StringPieceInputFile(data_));
  }
};

void RunBloaty(const InputFileFactory& factory, const std::string& name) {
  bloaty::RollupOutput output;
  bloaty::Options options;
  std::string error;
  options.add_filename("dummy_filename");
  options.set_disassemble_function(name);
  // No data sources: BloatyDoMain only takes the DisassembleFunction branch
  // when options.data_source_size() == 0.
  bloaty::BloatyMain(options, factory, &output, &error);
}

}  // namespace
}  // namespace bloaty

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) {
    return 0;
  }

  size_t name_len = data[0];
  if (name_len > 64) {
    name_len = 64;
  }
  if (size < 1 + name_len + 1) {
    return 0;
  }

  std::string name(reinterpret_cast<const char*>(data) + 1, name_len);
  const char* file_data = reinterpret_cast<const char*>(data) + 1 + name_len;
  size_t file_size = size - 1 - name_len;

  bloaty::StringPieceInputFileFactory factory(string_view(file_data, file_size));
  bloaty::RunBloaty(factory, name);
  return 0;
}
