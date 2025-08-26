
#ifndef AFL_MUTATIONS_H
#define AFL_MUTATIONS_H

#include "../core/globals.h"
#include "../utils/random.h"
#include "../utils/system.h"
#include "../utils/timing.h"
#include "../analysis/bitmap.h"
#include "../core/queue.h"
#include "../io/stats.h"
#include "../core/executor.h"
#include "../io/file_ops.h"

/* External variables used across mutation modules */
extern u8* stage_name;
extern u8* stage_short;
extern s32 stage_cur, stage_max;
extern s32 stage_cur_byte, stage_cur_val;
extern u8  stage_val_type;
extern u64 stage_finds[32], stage_cycles[32];

extern struct queue_entry *queue_cur;
extern u32 queued_paths, pending_favored;
extern u64 queue_cycle;
extern u8 dumb_mode;
extern s32 splicing_with;

/* 模糊测试阶段枚举在globals.h中定义 */

/* 主要的模糊测试函数 */
u8 fuzz_one(char** argv);

/* 子变异函数 */
u32 choose_block_len(u32 limit);
u32 calculate_score(struct queue_entry* q);
u8 could_be_bitflip(u32 xor_val);
u8 could_be_arith(u32 old_val, u32 new_val, u8 blen);
u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le);

/* write_to_testcase is defined in executor.c */
/* write_with_gap is defined in file_ops.c */

/* 校准相关 */
u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem, u32 handicap, u8 from_queue);
void examine_map(void);

/* 初始化和清理函数 */
void setup_post(void);
void load_auto(void);
void load_extras(u8* dir);
void destroy_extras(void);

/* 辅助函数 */
void maybe_add_auto(u8* mem, u32 len);
u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf);
u8 memcmp_nocase(u8* m1, u8* m2, u32 len);

#endif /* AFL_MUTATIONS_H */