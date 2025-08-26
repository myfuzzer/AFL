/*
   american fuzzy lop - 文件操作模块
   ===============================

   包含文件操作相关函数声明
*/

#ifndef AFL_FILE_OPS_H
#define AFL_FILE_OPS_H

#include "../core/globals.h"

/* 文件操作函数 */
void link_or_copy(u8* old_path, u8* new_path);
void write_to_testcase(void* mem, u32 len);
void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len);
void read_testcases(void);

#endif /* AFL_FILE_OPS_H */