/*
   american fuzzy lop - 系统工具模块
   ===============================

   包含系统相关工具函数声明
*/

#ifndef AFL_SYSTEM_H
#define AFL_SYSTEM_H

#include "../core/globals.h"

/* 系统工具函数 */
void save_auto(void);
void fix_up_banner(u8* name);
void check_if_tty(void);
void check_term_size(void);
void get_core_count(void);

#ifdef HAVE_AFFINITY
void bind_to_free_cpu(void);
#endif

#endif /* AFL_SYSTEM_H */