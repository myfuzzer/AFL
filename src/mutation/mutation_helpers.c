#include "mutations.h"

/* 用于在 fuzz_one() 中为块操作选择随机块长度的辅助函数。
   只要 max_len > 0，就不会返回零。*/

u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m) rlim = 1;

  switch (UR(rlim)) {

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

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

}



/* 计算案例期望得分以调整 havoc 模糊测试的长度。
   fuzz_one() 的辅助函数。也许其中一些常量应该
   放入 config.h。*/

u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* 根据此路径的执行速度与
     全局平均值进行比较来调整分数。乘数范围为 0.1x 到 3x。快速输入
     模糊测试成本较低，因此我们给它们更多的播出时间。*/

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* 根据位图大小调整分数。工作理论是，更好的
     覆盖率转化为更好的目标。乘数从 0.25x 到 3x。*/

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* 根据障碍调整分数。障碍与我们了解
     此路径的时间成正比。后来者被允许运行
     更长的时间，直到他们赶上其他人。*/

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* 基于输入深度的最终调整，假设模糊测试
     更深的测试用例更有可能揭示传统模糊测试器无法
     发现的东西。*/

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default:        perf_score *= 5;

  }

  /* 确保我们不超过限制。*/

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;

}



/* 辅助函数，用于查看特定更改 (xor_val = old ^ new) 是否可能
   是 afl-fuzz 尝试的长度和步长的确定性位翻转的产物。
   这用于避免在位翻转之后的一些确定性模糊测试操作中出现重复。
   如果 xor_val 为零，我们还返回 1，这意味着旧值和尝试的新值
   相同，执行将是浪费时间。*/

u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) return 1;

  /* 向左移位直到第一个位被设置。*/

  while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

  /* 1、2 和 4 位模式在任何地方都可以。*/

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8、16 和 32 位模式仅在移位因子
     可被 8 整除时才有效，因为这是这些操作的步长。*/

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;

}


/* 辅助函数，用于查看特定值是否可以通过
   算术运算达到。用于类似目的。*/

u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* 查看对任何字节的一字节调整是否可以产生此结果。*/

  for (i = 0; i < blen; i++) {

    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* 如果只有一个字节不同并且值在范围内，则返回 1。*/

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* 查看对任何字节的两字节调整是否会产生此结果。*/

  diffs = 0;

  for (i = 0; i < blen / 2; i++) {

    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) { diffs++; ov = a; nv = b; }

  }

  /* 如果只有一个字不同并且值在范围内，则返回 1。*/

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* 最后，让我们对 dword 做同样的事情。*/

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

  }

  return 0;

}



/* 最后但并非最不重要的一点是，一个类似的辅助函数，用于查看插入一个
   有趣的整数是否是多余的，因为已经为较短的 blen 完成了插入。
   最后一个参数 (check_le) 在调用者已经为当前 blen 执行了 LE 插入
   并希望查看传入 new_val 的 BE 变体是否唯一时设置。*/

u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) return 1;

  /* 查看从 interesting_8 在 old_val 上进行的一字节插入是否可以
     产生 new_val。*/

  for (i = 0; i < blen; i++) {

    for (j = 0; j < sizeof(interesting_8); j++) {

      u32 tval = (old_val & ~(0xff << (i * 8))) |
                 (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* 除非我们还被要求检查两字节 LE 插入
     作为 BE 尝试的准备，否则在此处退出。*/

  if (blen == 2 && !check_le) return 0;

  /* 查看在 old_val 上进行的两字节插入是否可以给我们 new_val。*/

  for (i = 0; i < blen - 1; i++) {

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* 仅当 blen > 2 时才在此处继续。*/

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* 查看四字节插入是否可以产生相同的结果
       （仅限 LE）。*/

    for (j = 0; j < sizeof(interesting_32) / 4; j++)
      if (new_val == (u32)interesting_32[j]) return 1;

  }

  return 0;

}

