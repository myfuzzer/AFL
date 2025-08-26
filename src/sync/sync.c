/*
   american fuzzy lop - 同步和分布式模块实现
   =========================================

   实现分布式模糊测试的同步功能
*/

#include "sync.h"
#include "../utils/timing.h"
#include "../io/file_ops.h"

extern u8* sync_dir;
extern u8* sync_id; 
extern u32 master_id, master_max;
extern u8 force_deterministic, skip_deterministic, use_splicing;
extern u8 dumb_mode;

/* 验证并修复使用-S时的out_dir和sync_dir */
void fix_up_sync(void) {

  u8* x = sync_id;

  if (dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic) {

    if (force_deterministic)
      FATAL("use -S instead of -M -d");
    else
      FATAL("-S already implies -d");

  }

  while (*x) {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;

  }

  if (strlen(sync_id) > 32) FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir  = x;

  if (!force_deterministic) {
    skip_deterministic = 1;
    use_splicing = 1;
  }

}

/* 恢复时，尝试找到开始位置。这在没有-S的情况下对正常的单实例模糊测试也有意义 */
u32 find_start_position(void) {

  static u8 tmp[4096]; /* 应该足够了 */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return 0;

  if (in_place_resume) fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return 0;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path          : ");
  if (!off) return 0;

  ret = atoi(off + 20);
  if (ret >= queued_paths) ret = 0;
  return ret;

}

/* 从其他模糊器抓取有趣的测试用例 - 简化版本 */
void sync_fuzzers(char** argv) {
  
  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);

  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

  stage_name = "sync";
  stage_max  = stage_cur = 0;

  /* 查看目录中的每个模糊器 */
  
  while ((sd_ent = readdir(sd))) {

    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* 跳过点文件、我们自己的输出目录等 */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue;

    /* 简化的同步逻辑 - 实际实现需要更复杂的处理 */

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    
    ACTF("正在与 '%s' 同步...", sd_ent->d_name);

    /* 在这里应该实现完整的同步逻辑 */
    /* 包括：检查.synced文件、读取测试用例、校验等 */

  }

  closedir(sd);

}