/*
   american fuzzy lop - 时间处理模块
   =================================

   包含时间相关的工具函数声明
*/

#ifndef AFL_TIMING_H
#define AFL_TIMING_H

#include "../core/globals.h"

/* 时间相关函数 */
u64 get_cur_time(void);
u64 get_cur_time_us(void);
u8* DTD(u64 cur_ms, u64 event_ms);

/* 格式化函数 */
u8* DI(u64 val);
u8* DMS(u64 val);

/* 哈希函数 */
u32 hash32(const void* key, u32 len, u32 seed);

#endif /* AFL_TIMING_H */