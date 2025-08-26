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

/* 设置运行横幅 */
void fix_up_banner(u8* name) {

  if (!use_banner) {

    if (sync_id) {

      use_banner = sync_id;

    } else {

      u8* trim = strrchr(name, '/');
      if (!trim) use_banner = name; else use_banner = trim + 1;

    }

  }

  if (strlen(use_banner) > 40) {

    u8* tmp = ck_alloc(44);
    sprintf(tmp, "%.40s...", use_banner);
    use_banner = tmp;

  }

}

/* 检查是否在TTY上运行 */
void check_if_tty(void) {

  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("由于设置了AFL_NO_UI，禁用UI。");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("看起来我们没有在tty上运行，所以我会少一些详细信息。");
      not_on_tty = 1;
    }

    return;
  }

}

/* 调整大小后检查终端尺寸 */
void check_term_size(void) {

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row < 25 || ws.ws_col < 80) term_too_small = 1;

}

/* 获取逻辑CPU核心数 */
void get_core_count(void) {

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);
  if (cpu_core_count < 1) cpu_core_count = 1;

}

#ifdef HAVE_AFFINITY

/* 绑定到可用的CPU核心 */
void bind_to_free_cpu(void) {

  cpu_set_t c;

  u8 cpu_used[4096];
  u32 i;

  if (cpu_core_count < 2) return;
  if (getenv("AFL_NO_AFFINITY")) return;

  memset(cpu_used, 0, sizeof(cpu_used));

  /* 查看当前使用的核心... */

  CPU_ZERO(&c);

  if (sched_getaffinity(0, sizeof(c), &c))
    PFATAL("sched_getaffinity failed");

  for (i = 0; i < cpu_core_count; i++)
    if (CPU_ISSET(i, &c)) cpu_used[i] = 1;

  for (i = 1; i < cpu_core_count; i++)
    if (!cpu_used[i]) break;

  if (cpu_to_bind_given) {

    if (cpu_to_bind >= cpu_core_count)
      FATAL("核心数少于您的目标.");

    if (cpu_used[cpu_to_bind])
      FATAL("核心 #%u 已被使用.", cpu_to_bind);

    i = cpu_to_bind;
    
  } else {

    for (i = 0; i < cpu_core_count; i++) if (!cpu_used[i]) break;
    
  }

  if (i == cpu_core_count) {

    SAYF("\n" cLRD "[-] " cRST
         "哦，看起来系统上所有 %u 个CPU核心都分配给了\n"
         "    afl-fuzz的其他实例（或类似的CPU锁定任务）。启动\n"
         "    另一个模糊器在这台机器上可能是一个坏计划，但如果您是\n"
         "    绝对确定，您可以设置AFL_NO_AFFINITY并重试。\n",
         cpu_core_count);

    FATAL("No more free CPU cores");

  }

  OKF("找到了一个空闲的CPU核心，绑定到 #%u。", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    PFATAL("sched_setaffinity failed");

}

#endif /* HAVE_AFFINITY */