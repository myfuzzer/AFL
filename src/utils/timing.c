/*
   american fuzzy lop - 时间处理模块实现
   =====================================

   实现时间相关的工具函数
*/

#include "timing.h"

/* 用于格式化整数显示的函数 */
u8* DI(u64 val) {
  static u8 tmp[12];
  if (val < 1000) {
    sprintf(tmp, "%llu", val);
  } else if (val < 1000 * 1000) {
    sprintf(tmp, "%0.1fk", ((double)val) / 1000);
  } else if (val < 1000 * 1000 * 1000) {
    sprintf(tmp, "%0.1fM", ((double)val) / 1000000);
  } else {
    sprintf(tmp, "%0.1fG", ((double)val) / 1000000000);
  }
  return tmp;
}

/* 为内存大小描述整数 */
u8* DMS(u64 val) {
  static u8 tmp[12][16];
  static u8 cur;
  
  cur = (cur + 1) % 12;
  
  if (val < 1024) {
    sprintf(tmp[cur], "%llu B", val);
  } else if (val < 1024 * 1024) {
    sprintf(tmp[cur], "%0.1f kB", ((double)val) / 1024);
  } else if (val < 1024 * 1024 * 1024) {
    sprintf(tmp[cur], "%0.1f MB", ((double)val) / 1024 / 1024);
  } else {
    sprintf(tmp[cur], "%0.1f GB", ((double)val) / 1024 / 1024 / 1024);
  }
  
  return tmp[cur];
}

/* 获取毫秒级的unix时间 */
u64 get_cur_time(void) {
  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);
}

/* 获取微秒级的unix时间 */
u64 get_cur_time_us(void) {
  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

/* 描述时间增量。返回一个静态缓冲区，34个字符或更少 */
u8* DTD(u64 cur_ms, u64 event_ms) {
  static u8 tmp[64];
  u64 delta;
  s32 t_d, t_h, t_m, t_s;

  if (!event_ms) return "none seen yet";

  delta = cur_ms - event_ms;

  t_d = delta / 1000 / 60 / 60 / 24;
  t_h = (delta / 1000 / 60 / 60) % 24;
  t_m = (delta / 1000 / 60) % 60;
  t_s = (delta / 1000) % 60;

  sprintf(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
  return tmp;
}

/* 简单的哈希函数 - 来自 Bob Jenkins */
u32 hash32(const void* key, u32 len, u32 seed) {

  const u8* data = (const u8*)key;
  u32 h1 = seed;
  u32 c1 = 0xcc9e2d51;
  u32 c2 = 0x1b873593;
  u32 i;

  for (i = 0; i < len; i++) {
    
    u32 k1 = data[i];
    k1 *= c1;
    k1 = (k1 << 15) | (k1 >> 17);
    k1 *= c2;

    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >> 19);
    h1 = h1 * 5 + 0xe6546b64;
    
  }

  h1 ^= len;
  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}