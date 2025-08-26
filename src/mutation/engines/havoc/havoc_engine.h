#ifndef HAVOC_ENGINE_H
#define HAVOC_ENGINE_H

#include "../../core/fuzz_context.h"

u8 fuzz_havoc_stage(char** argv, fuzz_context_t* ctx, u32 splice_cycle, u8 doing_det);

#endif