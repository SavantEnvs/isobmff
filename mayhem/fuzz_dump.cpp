/*
 * mayhem/fuzz_dump.cpp — in-process libFuzzer harness for ISOBMFF-Dump's actual behaviour: the
 * `SkipMDATData` parse option and the full box-tree stringification via `File::operator<<`, the
 * two pieces of `ISOBMFF-Dump/main.cpp` that `fuzz_parser.cpp` doesn't exercise (it only walks
 * `GetBoxes()`, never the print/stringify path). Runs in-process (no fork/exec, no file I/O), so
 * it gets the same real coverage far faster — and coverage-guided, not black-box — than the
 * `dump` binary target (Mayhemfile_dump, cmd-mode over a temp file per exec).
 *
 * `dump`'s own file-argument CLI is left in place unmodified (build/dump, build-oracle/dump) —
 * this harness replaces it as the primary fuzz *signal* for this surface, not the binary itself.
 */
#include <cstdint>
#include <cstddef>
#include <memory>
#include <sstream>
#include <vector>

#include "ISOBMFF/File.hpp"
#include "ISOBMFF/Parser.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> bytes(data, data + size);

    ISOBMFF::Parser parser;
    parser.AddOption(ISOBMFF::Parser::Options::SkipMDATData);
    try {
        parser.Parse(bytes);
    } catch (const std::runtime_error &) {
        return 0;   /* malformed input rejected cleanly — not a bug */
    } catch (...) {
        return 0;
    }

    std::shared_ptr<ISOBMFF::File> file = parser.GetFile();
    if (file) {
        std::ostringstream oss;
        oss << *file;   /* exercise every box type's print/stringify path */
    }
    return 0;
}
