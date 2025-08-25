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
u32 choose_block_len(u32 limit);

#endif /* AFL_FILE_OPS_H */