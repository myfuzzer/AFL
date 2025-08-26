/*
   american fuzzy lop - 统计模块实现
   ===============================

   实现统计数据写入和显示功能
*/

#include "stats.h"
#include "../utils/timing.h"
#include "../analysis/bitmap.h"

extern u8* out_dir;
extern u64 start_time, total_execs, queue_cycle, last_path_time, last_crash_time, last_hang_time, last_crash_execs, slowest_exec_ms;
extern u32 queued_paths, queued_favored, queued_discovered, queued_imported, max_depth, current_entry;
extern u32 pending_favored, pending_not_fuzzed, queued_variable, exec_tmout;
extern u64 unique_crashes, unique_hangs;
extern u8* use_banner, *orig_cmdline;
extern u8 qemu_mode, dumb_mode, no_forkserver, crash_mode, persistent_mode, deferred_mode;
extern FILE* plot_file;
extern u8 virgin_bits[MAP_SIZE];
extern u32 var_byte_count;
extern u32 stats_update_freq;
extern u8 run_over10m;
extern volatile u8 stop_soon;
extern u64 cycles_wo_finds;

/* 前向声明 */
void save_auto(void);
void write_bitmap(void);

/* 为无人值守监控更新统计文件 */
void write_stats_file(double bitmap_cvg, double stability, double eps) {

  static double last_bcvg, last_stab, last_eps;
  static struct rusage usage;

  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("无法创建 '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() 失败");

  /* 保留最后的值，以防我们从另一个上下文调用，
     执行/秒统计等不容易获得 */

  if (!bitmap_cvg && !stability && !eps) {
    bitmap_cvg = last_bcvg;
    stability  = last_stab;
    eps        = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps  = eps;
  }

  fprintf(f, "开始时间        : %llu\n"
             "最后更新       : %llu\n"
             "模糊器进程号        : %u\n"
             "完成循环       : %llu\n"
             "完成执行        : %llu\n"
             "每秒执行     : %0.02f\n"
             "路径总数       : %u\n"
             "偏爱路径     : %u\n"
             "发现路径       : %u\n"
             "导入路径    : %u\n"
             "最大深度         : %u\n"
             "当前路径          : %u\n"
             "待处理偏爱      : %u\n"
             "待处理总数     : %u\n"
             "可变路径    : %u\n"
             "稳定性         : %0.02f%%\n"
             "位图覆盖        : %0.02f%%\n"
             "独特崩溃    : %llu\n"
             "独特挂起      : %llu\n"
             "最后路径         : %llu\n"
             "最后崩溃        : %llu\n"
             "最后挂起         : %llu\n"
             "自崩溃以来执行 : %llu\n"
             "执行超时      : %u\n"
             "AFL横幅        : %s\n"
             "AFL版本       : " VERSION "\n"
             "目标模式       : %s%s%s%s%s%s%s\n"
             "命令行      : %s\n"
             "最慢执行毫秒   : %llu\n",
             start_time / 1000, get_cur_time() / 1000, getpid(),
             queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
             queued_paths, queued_favored, queued_discovered, queued_imported,
             max_depth, current_entry, pending_favored, pending_not_fuzzed,
             queued_variable, stability, bitmap_cvg, unique_crashes,
             unique_hangs, last_path_time / 1000, last_crash_time / 1000,
             last_hang_time / 1000, total_execs - last_crash_execs,
             exec_tmout, use_banner,
             qemu_mode ? "qemu " : "", dumb_mode ? " dumb " : "",
             no_forkserver ? "no_forksrv " : "", crash_mode ? "crash " : "",
             persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
             (qemu_mode || dumb_mode || no_forkserver || crash_mode ||
              persistent_mode || deferred_mode) ? "" : "default",
             orig_cmdline, slowest_exec_ms);
             /* 忽略错误 */

  /* 从子进程获取rss值
     我们必须杀死forkserver进程并在调用getrusage之前调用waitpid */
  if (getrusage(RUSAGE_CHILDREN, &usage)) {
      WARNF("getrusage失败");
  } else if (usage.ru_maxrss == 0) {
    fprintf(f, "峰值RSS MB       : afl运行时不可用\n");
  } else {
#ifdef __APPLE__
    fprintf(f, "峰值RSS MB       : %zu\n", usage.ru_maxrss >> 20);
#else
    fprintf(f, "峰值RSS MB       : %zu\n", usage.ru_maxrss >> 10);
#endif /* ^__APPLE__ */
  }

  fclose(f);

}

/* 显示统计屏幕的大型函数！这在每stats_update_freq execve()调用时调用，
   以及其他几种情况下 */
void show_stats(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* 如果自上次UI更新以来没有足够的时间，则跳出 */
  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* 检查是否过了10分钟标记 */
  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;

  /* 计算平滑的执行速度统计 */
  if (!last_execs) {
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);
  } else {
    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* 如果速度有巨大（5倍以上）跳跃，更快重置指示器 */
    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);
  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* 告诉调用者何时联系我们（以execs为单位） */
  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* 做一些位图统计 */
  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes) 
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* 大约每分钟，更新模糊器统计并保存自动令牌 */
  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();

  }

  /* 时不时写入绘图数据 */
  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);
 
  }

  /* 尊重AFL_EXIT_WHEN_DONE和AFL_BENCH_UNTIL_CRASH */
  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE")) stop_soon = 2;

  if (unique_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;

  /* 如果我们不在TTY上，跳出 */
  if (not_on_tty) return;

  /* 计算一些温和有用的位图统计 */
  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* 现在，视觉效果... */
  if (clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();

  }

  SAYF(TERM_HOME);

  if (term_too_small) {

    SAYF(cBRI "您的终端太小，无法显示UI。\n"
         "请将终端窗口调整为至少80x25。\n" cRST);

    return;

  }

  /* 让我们从绘制居中横幅开始 */
  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner);
  banner_pad = (80 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s)",  crash_mode ? cPIN "peruvian were-rabbit" : 
          cYEL "american fuzzy lop", use_banner);

  SAYF("\n%s\n\n", tmp);

  /* 绘制框的"便利"快捷方式... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* 主啊，原谅我这个 */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH2 bHB
       bH bSTOP cCYA " overall results " bSTG bH5 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* 第一个队列循环：现在不要停止！ */
    if (queue_cycle == 1 || min_wo_finds < 15) strcpy(tmp, cMGN); else

    /* 后续循环，但我们仍在发现 */
    if (cycles_wo_finds < 25 || min_wo_finds < 30) strcpy(tmp, cYEL); else

    /* 长时间没有发现，没有测试用例尝试 */
    if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
      strcpy(tmp, cLGN);

    /* 默认：谨慎地OK停止？ */
    else strcpy(tmp, cLBL);

  }

  /* 这里会有更多的统计显示代码... */
  /* 为了节省空间，这里仅显示基本框架 */

  SAYF(bSTG bV bSTOP "        run time : " cRST "%-34s " bSTG bV bSTOP
       "  cycles done : %s%-5s  " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* 简化的统计输出 */
  SAYF(bSTG bV bSTOP "   last new path : " cRST "%-34s ",
       DTD(cur_ms, last_path_time));

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s  " bSTG bV "\n",
       DI(queued_paths));

  /* Timing and CPU usage */

  if (dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    if (cur_ms - last_path_time > 2 * 60 * 1000) strcpy(tmp, cPIN);
    else strcpy(tmp, cRST);

  }

  SAYF(bSTG bV bSTOP "  last uniq crash : " cRST "%-34s ",
       DTD(cur_ms, last_crash_time));

  if (unique_crashes) {

    sprintf(tmp, "%s%s", DI(unique_crashes), crash_mode ? cLRD : cRST);

  } else strcpy(tmp, cRST "none seen yet");

  SAYF(bSTG bV bSTOP "uniq crashes : " cRST "%-6s " bSTG bV "\n", tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs), crash_mode ? cLRD : cRST);

  SAYF(bSTG bV bSTOP "   last uniq hang : " cRST "%-34s " bSTG bV bSTOP
       "  uniq hangs : " cRST "%-6s " bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bSTG bV bSTOP "     exec speed : " cLRD "%-34s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bSTG bV bSTOP "     exec speed : " cRST "%-34s ", tmp);

  }

  sprintf(tmp, "%s (%0.02f%%)", DI(current_entry), ((double)current_entry * 100) / queued_paths);

  SAYF(bSTG bV bSTOP "  cur item : " cRST "%-8s " bSTG bV "\n", tmp);

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "0");

  SAYF(bSTG bV bSTOP "    coverage : " cRST "%-21s " bSTG bV bSTOP, tmp);

  if (t_bytes) sprintf(tmp, "%0.02f%% / %0.02f%%", t_byte_ratio, stab_ratio);
  else strcpy(tmp, "0.00%");

  SAYF(bSTG bV bSTOP " stability : " cRST "%-10s " bSTG bV "\n", tmp);

  if (dumb_mode) {

    SAYF(bSTG bV bSTOP "                                             " bSTG bV bSTOP
         "                   " bSTG bV "\n");

  }

  /* 更多统计信息将在这里... */

  SAYF(bSTG bLB bH30 bH20 bH2 bHB bH bSTOP cCYA " stage progress " bSTG bH2 bH30 bH5 bRB "\n");

  SAYF(bSTG bV bSTOP "  now trying : " cRST "%-21s " bSTG bV bSTOP, 
       stage_name ? stage_name : "init");

  if (stage_max) {

    sprintf(tmp, "%s (%0.02f%%)", DI(stage_cur), ((double)stage_cur * 100) / stage_max);

    SAYF(bSTG bV bSTOP " stage execs : " cRST "%-11s " bSTG bV "\n", tmp);

  } else {

    SAYF(bSTG bV bSTOP " stage execs : " cRST "%-11s " bSTG bV "\n", 
         DI(stage_cur));

  }

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored * 100) / queued_paths);

  SAYF(bSTG bV bSTOP "  favs found : " cRST "%-22s " bSTG bV bSTOP
       "  pending : " cRST "%-11s " bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!queued_variable) strcpy(tmp, cRST "fixed");
  else sprintf(tmp, cLRD "variable");

  SAYF(bSTG bV bSTOP "   new edges : " cRST "%-22s " bSTG bV bSTOP
       " var paths : " cRST "%-11s " bSTG bV "\n",
       DI(queued_discovered), tmp);

  sprintf(tmp, "%s (%s%s saved)",  DI(total_crashes),
          DI(unique_crashes), crash_mode ? cRST : "");

  if (crash_mode) {

    SAYF(bSTG bV bSTOP " crashes found : " cLRD "%-22s " bSTG bV bSTOP
         " imported : " cRST "%-11s " bSTG bV "\n", tmp, 
         sync_id ? DI(queued_imported) : "n/a");

  } else {

    SAYF(bSTG bV bSTOP " total crashes : " cRST "%-22s " bSTG bV bSTOP
         " imported : " cRST "%-11s " bSTG bV "\n", tmp,
         sync_id ? DI(queued_imported) : "n/a");

  }

  /* Show CPU utilization */

  if (cpu_core_count > 1) {

    u32 cur_runnable = get_runnable_processes();

    sprintf(tmp, "%.0f%% (%u out of %u)", 
            ((double)cur_runnable * 100) / cpu_core_count, cur_runnable, cpu_core_count);

    SAYF(bSTG bV bSTOP "      cpu usage : " cRST "%-22s " bSTG bV bSTOP
         "            : " cRST "%-11s " bSTG bV "\n", tmp, "");

  } else {

    SAYF(bSTG bV bSTOP "                                             " bSTG bV bSTOP
         "            : " cRST "%-11s " bSTG bV "\n", "");

  }

  SAYF(bSTG bLB bH5 bH2 bHB bH bSTOP cCYA " findings in depth " bSTG bH2 bH2 bHB bH5 bH2 bH30 bRB "\n");

  if (max_depth) {

    u32 i;

    for (i = 1; i <= max_depth; i++) {

      u32 depth_cnt = 0;
      struct queue_entry* q = queue;

      while (q) {
        if (q->depth == i) depth_cnt++;
        q = q->next;
      }

      sprintf(tmp, "depth %u : %u", i, depth_cnt);
      SAYF(bSTG bV bSTOP "  %s%-22s " bSTG bV bSTOP "            : " cRST "%-11s " bSTG bV "\n", 
           i == max_depth ? cLRD : cRST, tmp, "");

      if (i == 6) break;

    }

  } else {

    SAYF(bSTG bV bSTOP "                                             " bSTG bV bSTOP
         "            : " cRST "%-11s " bSTG bV "\n", "");

  }

  SAYF(bSTG bLB bH30 bH20 bH2 bH bHB bH bRB "\n" cRST RESET_G1);

  /* Provide some warnings if things get hairy. */

  if (queue_cur && queue_cur->var_behavior) {

    SAYF(cLRD "\n  Warning!" cRST
         " The current test case %s seems to have variable behavior across\n"
         "  multiple runs. This will lower the odds of spotting a crash, but\n"
         "  is probably not a big deal for coverage-based guidance.\n",
         queue_cur->fname);

    if (cur_ms - last_hang_time < 10000)
      SAYF(cLRD "  Warning!" cRST
           " Substantial processing delays may be caused by " cLRD "timeouts" cRST ". For\n"
           "  tips on dealing with this situation, please see %s/README.\n",
           doc_path);

  }

  if (cur_ms - start_time > 10000 && cur_ms - start_time < 60000 && 
      !queue_cycle) {

    SAYF("\n  Hmm, looks like the target binary is pretty slow! See %s/README\n"
         "  for a few handy tips on how to speed up the process and fix issues.\n",
         doc_path);

  }

  SAYF(CURSOR_SHOW cRST);

}

/* 如果有理由，更新绘图文件 */
void maybe_update_plot_file(double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored && 
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth) return;

  prev_qp  = queued_paths;
  prev_pf  = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce  = current_entry;
  prev_qc  = queue_cycle;
  prev_uc  = unique_crashes;
  prev_uh  = unique_hangs;
  prev_md  = max_depth;

  /* 文件中的字段：

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec */

  fprintf(plot_file, 
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps); /* 忽略错误 */

  fflush(plot_file);

}

/* 一个漂亮的复古统计屏幕！这在每个stats_update_freq执行调用时被调用，
   以及在其他几种情况下 */
void show_stats(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes;

  cur_ms = get_cur_time();

  /* 如果自上次UI更新以来没有足够的时间过去，则退出 */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* 检查我们是否过了10分钟标记 */

  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;

  /* 计算平滑的执行速度统计 */

  if (!last_execs) {
  
    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);

  } else {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* 如果速度有戏剧性的（5x+）跳跃，请更快地重置指示器 */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* 告诉调用者何时联系我们（以执行次数衡量） */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* 做一些位图统计 */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes) 
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* 大约每分钟，更新模糊器统计并保存自动令牌 */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();

  }

  /* 每隔一段时间，写入绘图数据 */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);
 
  }

  /* 遵循AFL_EXIT_WHEN_DONE和AFL_BENCH_UNTIL_CRASH */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE")) stop_soon = 2;

  /* 这里可以添加更多的UI显示逻辑 */

}