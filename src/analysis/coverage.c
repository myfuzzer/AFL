/*
   american fuzzy lop - 覆盖分析模块实现
   ==================================

   实现覆盖分析相关功能
*/

#include "coverage.h"

extern u8* trace_bits;
extern u8* out_dir;

/* 将位图数据写入文件 */
void write_bitmap(void) {
  
  u8* fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  s32 fd;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) PFATAL("无法创建 '%s'", fn);

  ck_write(fd, trace_bits, MAP_SIZE, fn);
  close(fd);
  ck_free(fn);

}