/*
   american fuzzy lop - 位图操作模块实现
   ====================================

   实现位图相关的操作函数
*/

#include "bitmap.h"

extern u8* trace_bits;
extern u8 bitmap_changed;

/* 计数类查找表（来自原始 afl-fuzz.c） */
static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};

static u16 count_class_lookup16[65536];

/* 将轨迹字节压缩到更小的位图中。我们实际上只是在这里删除计数信息。
   这只在偶尔调用，对于一些新路径 */
void minimize_bits(u8* dst, u8* src) {
  u32 i = 0;

  while (i < MAP_SIZE) {
    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;
  }
}

/* 检查当前执行路径是否给表带来了新的东西。
   更新virgin位以反映发现。如果唯一的变化是特定元组的命中计数，
   则返回1；如果看到新的元组则返回2。更新映射，因此后续调用将始终返回0 */
u8 has_new_bits(u8* virgin_map) {

#ifdef WORD_SIZE_64

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  u8   ret = 0;

  while (i--) {

    /* 为(*current & *virgin) == 0优化 - 即，当前位图中没有尚未从virgin映射中清除的位 - 
       因为这几乎总是这种情况 */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* 看起来我们还没有找到任何新的字节；看看current[]中的任何非零字节
           在virgin[]中是否是原始的 */

#ifdef WORD_SIZE_64

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^WORD_SIZE_64 */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

  return ret;

}

/* 计算提供的位图中设置的位数。用于状态屏幕每秒几次，不必很快 */
u32 count_bits(u8* mem) {
  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    /* 这在倒置的virgin位图上被调用；为稀疏数据优化 */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;
  }

  return ret;
}

#define FF(_b)  (0xff << ((_b) << 3))

/* 计算位图中设置的字节数。调用相当零星，主要是为了更新状态屏幕
   或校准和检查确认的新路径 */
u32 count_bytes(u8* mem) {
  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    if (!v) continue;
    if (v & FF(0)) ret++;
    if (v & FF(1)) ret++;
    if (v & FF(2)) ret++;
    if (v & FF(3)) ret++;
  }

  return ret;
}

/* 计算位图中设置的非255字节数。严格用于状态屏幕，每秒几次调用左右 */
u32 count_non_255_bytes(u8* mem) {
  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {
    u32 v = *(ptr++);

    /* 这在virgin位图上被调用，所以为最可能的情况优化 */

    if (v == 0xffffffff) continue;
    if ((v & FF(0)) != FF(0)) ret++;
    if ((v & FF(1)) != FF(1)) ret++;
    if ((v & FF(2)) != FF(2)) ret++;
    if ((v & FF(3)) != FF(3)) ret++;
  }

  return ret;
}

/* 初始化计数类查找16 */
void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) 
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] = 
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}