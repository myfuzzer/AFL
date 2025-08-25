/*
   american fuzzy lop - 主程序模块
   ===============================

   包含主函数和命令行处理相关声明
*/

#ifndef AFL_MAIN_H
#define AFL_MAIN_H

#include "../core/globals.h"

/* 主程序相关函数 */
void usage(u8* argv0);
void save_cmdline(u32 argc, char** argv);
char** get_qemu_argv(u8* own_loc, char** argv, int argc);

#ifndef AFL_LIB
int main(int argc, char** argv);
#endif

#endif /* AFL_MAIN_H */