/*
   american fuzzy lop - 系统工具模块实现
   ==================================

   实现系统相关工具函数
*/

#include "system.h"

extern u8* out_dir;
extern u8 auto_changed;
extern struct extra_data* a_extras;
extern u32 a_extras_cnt;

/* 保存自动生成的额外字典 */
void save_auto(void) {

  u32 i;

  if (!auto_changed) return;
  auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); i++) {

    u8* fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) PFATAL("无法创建 '%s'", fn);

    ck_write(fd, a_extras[i].data, a_extras[i].len, fn);

    close(fd);
    ck_free(fn);

  }

}