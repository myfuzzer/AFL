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

/* 将修改后的数据写入文件进行测试 */
void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {
    fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to open '%s'", out_file);
  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (!out_file) {
    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);
  } else close(fd);
}

/* 同上，但带有可调整的间隙。用于修剪 */
void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len) {

  s32 fd = out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (out_file) {
    fd = open(out_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) PFATAL("Unable to open '%s'", out_file);
  } else lseek(fd, 0, SEEK_SET);

  if (skip_at) ck_write(fd, mem, skip_at, out_file);
  if (tail_len) ck_write(fd, (u8*)mem + skip_at + skip_len, tail_len, out_file);

  if (!out_file) {
    if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);
  } else close(fd);
}

/* 读取输入目录中的所有测试用例，然后排队等待测试 */
void read_testcases(void) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* 自动检测非目录的输入文件... */
  fn = alloc_printf("%s/queue", in_dir);
  if (access(fn, F_OK)) ck_free(fn);

  ACTF("扫描 '%s'...", in_dir);

  /* 我们在这里使用scandir() + alphasort()，而不是opendir/readdir，
     因为这样我们可以获得确定性排序，这有助于在多个不同系统上的测试 */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {
    if (errno == ENOENT || errno == ENOTDIR)
      SAYF("\n" cLRD "[-] " cRST
           "输入目录 '%s' 似乎不存在或不是有效目录。", in_dir);
    PFATAL("Unable to open '%s'", in_dir);
  }

  if (shuffle_queue && nl_cnt > 1) {

    ACTF("随机化队列...");
    shuffle_ptrs((void**)nl, nl_cnt);

  }

  for (i = 0; i < nl_cnt; i++) {

    struct stat st;

    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8  passed_det = 0;

    free(nl[i]); /* 不是通过ck_free分配的 */

    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* 这也过滤掉目录，等等 */
    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {
      ck_free(fn);
      ck_free(dfn);
      continue;
    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
            DMS(st.st_size), DMS(MAX_FILE));

    /* 检查元数据以查看确定性步骤是否已完成。我们不想重复这些！*/
    if (!access(dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn, st.st_size, passed_det);
  }

  free(nl); /* 不是通过ck_free分配的 */

  if (!queued_paths) {
    SAYF("\n" cLRD "[-] " cRST
         "看起来输入目录中没有有效的测试用例！");
    FATAL("No usable test cases in '%s'", in_dir);
  }

  last_path_time = 0;
  queued_at_start = queued_paths;

  ACTF("共导入 %u 个测试用例。", queued_paths);

}