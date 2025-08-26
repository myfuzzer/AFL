/*
   american fuzzy lop - 位图操作模块
   =================================

   包含位图相关操作函数声明
*/

#ifndef AFL_BITMAP_H
#define AFL_BITMAP_H

#include "../core/globals.h"

/* 位图操作函数 */
void minimize_bits(u8* dst, u8* src);
u8 has_new_bits(u8* virgin_map);
u32 count_bits(u8* mem);
u32 count_bytes(u8* mem);
u32 count_non_255_bytes(u8* mem);

/* 计数类初始化 */
void init_count_class16(void);

/* 轨迹处理函数 */
#ifdef WORD_SIZE_64
void simplify_trace(u64* mem);
#else
void simplify_trace(u32* mem);
#endif
void classify_counts(u64* mem);

/* 位图文件操作 */
void read_bitmap(u8* fname);

/* 辅助函数 */
void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last);

#endif /* AFL_BITMAP_H */