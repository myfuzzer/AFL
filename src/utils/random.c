/*
   american fuzzy lop - 随机数生成模块实现
   =======================================

   实现随机数生成相关函数
*/

#include "random.h"

extern u32 rand_cnt;
extern s32 dev_urandom_fd;

/* 生成随机数（从0到limit-1）。这可能有轻微的偏差 */
u32 UR(u32 limit) {
  if (unlikely(!rand_cnt--)) {
    u32 seed[2];

    ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

    srandom(seed[0]);
    rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);
  }

  return random() % limit;
}

/* 打乱指针数组。可能有轻微的偏差 */
void shuffle_ptrs(void** ptrs, u32 cnt) {
  u32 i;

  for (i = 0; i < cnt - 2; i++) {
    u32 j = i + UR(cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;
  }
}