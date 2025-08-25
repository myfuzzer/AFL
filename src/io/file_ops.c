/*
   american fuzzy lop - 文件操作模块实现
   ==================================

   实现文件相关操作函数
*/

#include "file_ops.h"
#include "../utils/random.h"

/* 创建硬链接，如果失败则复制文件 */
void link_or_copy(u8* old_path, u8* new_path) {

  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8* tmp;

  if (!i) return;

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0) PFATAL("无法打开 '%s'", old_path);

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0) PFATAL("无法创建 '%s'", new_path);

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) 
    ck_write(dfd, tmp, i, new_path);

  if (i < 0) PFATAL("读取 '%s' 失败", old_path);

  ck_free(tmp);
  close(sfd);
  close(dfd);

}

/* 为各种模糊测试操作选择一个合理的块长度。通常，这将是一个随机数
   从1到HAVOC_BLK_LARGE，但偶尔，它可能会更大，最多HAVOC_BLK_XL */

u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(limit, HAVOC_BLK_XL);

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