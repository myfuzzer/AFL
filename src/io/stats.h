/*
   american fuzzy lop - 统计模块
   ===========================

   包含统计相关函数声明
*/

#ifndef AFL_STATS_H
#define AFL_STATS_H

#include "../core/globals.h"

/* 统计函数 */
void write_stats_file(double bitmap_cvg, double stability, double eps);
void maybe_update_plot_file(double bitmap_cvg, double eps);
void show_stats(void);

#endif /* AFL_STATS_H */