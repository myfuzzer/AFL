
#ifndef AFL_FILE_OPS_H
#define AFL_FILE_OPS_H

#include "../core/globals.h"

/* 文件命名前缀定义 */
#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

/* 文件操作函数 */
void link_or_copy(u8* old_path, u8* new_path);
void write_to_testcase(void* mem, u32 len);
void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len);
void read_testcases(void);
void setup_dirs_fds(void);
void setup_stdio_file(void);
void pivot_inputs(void);
u8* describe_op(u8 hnb);
void write_crash_readme(void);
void nuke_resume_dir(void);

#endif /* AFL_FILE_OPS_H */