/*
   american fuzzy lop - 同步和分布式模块
   ====================================

   包含分布式模糊测试同步功能的声明
*/

#ifndef AFL_SYNC_H
#define AFL_SYNC_H

#include "../core/globals.h"

/* 同步相关函数 */
void sync_fuzzers(char** argv);
void fix_up_sync(void);
u32 find_start_position(void);

/* 分布式状态管理 */
void write_stats_file(double bitmap_cvg, double stability, double eps);
void read_foreign_testcases(char** argv);

#endif /* AFL_SYNC_H */