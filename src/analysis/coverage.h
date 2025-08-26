/*
   american fuzzy lop - 覆盖分析模块
   =================================

   包含覆盖分析相关函数声明
*/

#ifndef AFL_COVERAGE_H
#define AFL_COVERAGE_H

#include "../core/globals.h"

/* 覆盖分析函数 */
void write_bitmap(void);
void check_map_coverage(void);

#endif /* AFL_COVERAGE_H */