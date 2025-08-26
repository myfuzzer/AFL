
#include "coverage.h"
#include "bitmap.h"

extern u8* trace_bits;
extern u8* out_dir;



/* 将位图写入文件。位图主要用于秘密的
   -B 选项，以便将单独的模糊测试会话集中在特定的
   有趣的输入上，而无需重新发现所有其他输入。*/

void write_bitmap(void) {

  u8* fname;
  s32 fd;

  if (!bitmap_changed) return;
  bitmap_changed = 0;

  fname = alloc_printf("%s/fuzz_bitmap", out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_write(fd, virgin_bits, MAP_SIZE, fname);

  close(fd);
  ck_free(fname);

}

/* 检查映射覆盖率。为第一个测试用例调用一次。*/

void check_map_coverage(void) {

  u32 i;

  if (count_bytes(trace_bits) < 100) return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (trace_bits[i]) return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");

}
