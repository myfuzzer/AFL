#ifndef FUZZ_ENGINE_H
#define FUZZ_ENGINE_H

#include "fuzz_context.h"
#include "../engines/bitflip/bitflip_engine.h"
#include "../engines/arithmetic/arithmetic_engine.h"
#include "../engines/interesting/interesting_engine.h"
#include "../engines/dictionary/dictionary_engine.h"
#include "../engines/havoc/havoc_engine.h"
#include "../engines/splice/splice_engine.h"

// 重构后的主引擎函数
u8 fuzz_one_refactored(char** argv);

// 初始化和预处理函数
u8 init_and_preprocess(char** argv, fuzz_context_t* ctx);
u8 handle_calibration(char** argv, fuzz_context_t* ctx);
u8 handle_trimming(char** argv, fuzz_context_t* ctx);

#endif