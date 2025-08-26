#ifndef DICTIONARY_ENGINE_H
#define DICTIONARY_ENGINE_H

#include "../../core/fuzz_context.h"

u8 fuzz_user_extras_over(char** argv, fuzz_context_t* ctx);
u8 fuzz_user_extras_insert(char** argv, fuzz_context_t* ctx);
u8 fuzz_auto_extras_over(char** argv, fuzz_context_t* ctx);
u8 fuzz_dictionary_stages(char** argv, fuzz_context_t* ctx);

#endif