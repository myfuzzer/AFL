/*
   american fuzzy lop - 变异算法模块实现
   ===================================

   实现各种模糊测试变异策略
*/

#include "mutations.h"
#include "../utils/random.h"
#include "../analysis/bitmap.h"
#include "../core/executor.h"
#include "../io/file_ops.h"

extern u8* stage_name;
extern u8* stage_short;
extern s32 stage_cur, stage_max;
extern s32 stage_cur_byte, stage_cur_val;
extern u8  stage_val_type;
extern u64 stage_finds[32], stage_cycles[32];

extern struct queue_entry *queue_cur;
extern u32 queued_paths, pending_favored, queue_cycle;
extern u8 dumb_mode;
extern s32 splicing_with;

/* 效应器映射 - 跟踪哪些字节影响程序行为 */
u8 eff_map[MAP_SIZE];

/* 选择随机块长度用于块操作 */
u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cur->len, limit);

  switch (UR(3)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: 
             if (UR(10)) {
               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;
             } else {
               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;
             }
  }

  if (min_value >= rlim) min_value = 1;

  return min_value + UR(MIN(max_value, rlim) - min_value + 1);
}

/* 计算用例期望评分以调整havoc模糊长度 */
u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* 调整执行速度 */
  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* 调整路径深度 */
  if (q->handicap >= 4) {
    perf_score *= 4;
    q->handicap -= 4;
  } else if (q->handicap) {
    perf_score *= 2;
    q->handicap--;
  }

  /* 确保最小评分 */
  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;
}

/* 帮助函数：查看特定更改是否可能是位翻转操作的结果 */
u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (xor_val == 1 || xor_val == 3 || xor_val == 15 ||
      xor_val == 255 || xor_val == 65535 || xor_val == 0xffffffff) return 1;

  while (sh < 32) {
    if (xor_val == (1U << sh) || xor_val == (3U << sh) ||
        xor_val == (15U << sh) || xor_val == (255U << sh)) return 1;
    sh++;
  }

  return 0;
}

/* 帮助函数：查看特定值是否可通过算术操作达到 */
u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* 看看是否是位翻转 */
  if (could_be_bitflip(old_val ^ new_val)) return 1;

  /* 检查算术操作（加/减） */
  if (blen == 1) {
    diffs = ((u8)old_val) ^ ((u8)new_val);
    if (diffs <= 35) return 1;
  }

  if (blen == 2) {
    diffs = ((u16)old_val) ^ ((u16)new_val);
    if (diffs <= 35 || SWAP16(diffs) <= 35) return 1;
  }

  if (blen == 4) {
    diffs = old_val ^ new_val;
    if (diffs <= 35 || SWAP32(diffs) <= 35) return 1;
  }

  return 0;
}

/* 简化的模糊测试主函数 - 这是一个复杂函数的简化版本 */
u8 fuzz_one(char** argv) {
  
  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in;
  u32 orig_perf, perf_score = 100;
  u8  ret_val = 1, doing_det = 0;

  /* 简单的概率跳过逻辑 */
  if (pending_favored) {
    if ((queue_cur->was_fuzzed || !queue_cur->favored) && UR(100) < 90) 
      return 1;
  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {
    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {
      if (UR(100) < 75) return 1;
    } else {
      if (UR(100) < 95) return 1;
    }
  }

  /* 为简化，此处只实现基本框架 */
  /* 实际的变异算法需要从原版完整移植 */
  
  SAYF("执行变异测试用例: %s\n", queue_cur->fname);
  
  /* 标记为已模糊测试 */
  queue_cur->was_fuzzed = 1;
  
  return 0;
}

/* 校准测试用例 - 简化版本 */
u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem, u32 handicap, u8 from_queue) {
  
  static u8 first_trace[MAP_SIZE];
  
  u8 fault = 0, new_bits = 0, var_detected = 0;
  u64 start_us, stop_us;

  /* 简化的校准逻辑 */
  stage_name = "calibration";
  stage_max = CAL_CYCLES;

  for (stage_cur = 0; stage_cur < CAL_CYCLES; stage_cur++) {

    u32 cksum;

    if (!from_queue && !stage_cur)
      write_to_testcase(use_mem, q->len);

    fault = run_target(argv, exec_tmout);

    /* 处理故障情况 */
    if (stop_soon || fault != crash_mode) {
      ret_val = FAULT_TMOUT;
      break;
    }

    if (!stage_cur) {
      first_run = 0;
      memcpy(first_trace, trace_bits, MAP_SIZE);
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {
      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (q->exec_cksum) {
        u32 i;
        for (i = 0; i < MAP_SIZE; i++) {
          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {
            var_bytes[i] = 1;
            stage_max = CAL_CYCLES_LONG;
          }
        }
        var_detected = 1;
      } else {
        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);
      }
    }
  }

  if (new_bits) {
    queued_with_cov++;
  }

  return fault;
}