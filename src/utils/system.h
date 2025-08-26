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
void setup_signal_handlers(void);
void check_asan_opts(void);
void check_crash_handling(void);
void check_cpu_governor(void);
void detect_file_args(char** argv);
u32 next_p2(u32 val);
double get_runnable_processes(void);
void handle_stop_sig(int sig);
void handle_skipreq(int sig);
void handle_timeout(int sig);
void handle_resize(int sig);
void check_binary(u8* fname);

#ifdef HAVE_AFFINITY
void bind_to_free_cpu(void);
#endif

#endif /* AFL_SYSTEM_H */