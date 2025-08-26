#include "mutations.h"
#include "core/fuzz_engine.h"

/* eff_map is defined in globals.c */

/* Take the current entry from the queue, fuzz it for a while. This
   function has been refactored into modular components. Returns 0 if 
   fuzzed successfully, 1 if skipped or bailed out. */

u8 fuzz_one(char** argv) {
    // 使用重构后的模块化引擎
    return fuzz_one_refactored(argv);
}