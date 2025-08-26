/*
   american fuzzy lop - 变异算法模块
   =================================

   包含各种模糊测试变异策略的声明
*/

#ifndef AFL_MUTATIONS_H
#define AFL_MUTATIONS_H

#include "../core/globals.h"

/* 模糊测试阶段枚举（从globals.h移动到这里） */
enum {
  /* 位翻转 */
  STAGE_FLIP1,
  STAGE_FLIP2,  
  STAGE_FLIP4,
  STAGE_FLIP8,
  STAGE_FLIP16,
  STAGE_FLIP32,
  /* 算术操作 */
  STAGE_ARITH8,
  STAGE_ARITH16,
  STAGE_ARITH32,
  /* 有趣值替换 */
  STAGE_INTEREST8,
  STAGE_INTEREST16,
  STAGE_INTEREST32,
  /* 字典条目 */
  STAGE_EXTRAS_UO,
  STAGE_EXTRAS_UI,
  STAGE_EXTRAS_AO,
  /* 乱序变异和拼接 */
  STAGE_HAVOC,
  STAGE_SPLICE
};

/* 主要的模糊测试函数 */
u8 fuzz_one(char** argv);

/* 子变异函数 */
u32 choose_block_len(u32 limit);
u32 calculate_score(struct queue_entry* q);
u8 could_be_bitflip(u32 xor_val);
u8 could_be_arith(u32 old_val, u32 new_val, u8 blen);
u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le);

/* 辅助函数 */
u8 eff_map[MAP_SIZE];
void write_to_testcase(void* mem, u32 len);
void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len);

/* 校准相关 */
u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem, u32 handicap, u8 from_queue);
void examine_map(void);

#endif /* AFL_MUTATIONS_H */