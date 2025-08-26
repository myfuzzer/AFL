
#ifndef AFL_EXECUTOR_H
#define AFL_EXECUTOR_H

#include "globals.h"

/* 执行相关函数 */
u8 run_target(char** argv, u32 timeout);
void write_to_testcase(void* mem, u32 len);
void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len);
u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem, u32 handicap, u8 from_queue);
u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault);
u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len);
void check_binary(u8* fname);
void perform_dry_run(char** argv);

#endif /* AFL_EXECUTOR_H */