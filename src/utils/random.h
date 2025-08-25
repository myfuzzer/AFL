/*
   american fuzzy lop - 随机数生成模块
   ===================================

   包含随机数生成相关函数声明
*/

#ifndef AFL_RANDOM_H
#define AFL_RANDOM_H

#include "../core/globals.h"

/* 随机数生成函数 */
u32 UR(u32 limit);
void shuffle_ptrs(void** ptrs, u32 cnt);

#endif /* AFL_RANDOM_H */