/*
   american fuzzy lop - 主程序模块实现
   ===================================

   实现主函数和命令行处理
*/

#include "main.h"
#include "../utils/timing.h"
#include "../utils/system.h"
#include "../utils/random.h"
#include "../analysis/bitmap.h"
#include "../core/queue.h"
#include "../core/executor.h"
#include "../io/stats.h"
#include "../io/file_ops.h"
#include "../sync/sync.h"
#include "../mutation/mutations.h"

/* 显示使用提示 */
void usage(u8* argv0) {
  SAYF("\n🔧 AFL-FUZZ (模块化重构版本) 🔧\n");
  SAYF("=====================================\n");
  SAYF("%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "必需参数:\n\n"

       "  -i dir        - 包含测试用例的输入目录\n"
       "  -o dir        - 模糊测试发现的输出目录\n\n"

       "执行控制设置:\n\n"

       "  -f file       - 被模糊程序读取的位置 (stdin)\n"
       "  -t msec       - 每次运行的超时 (自动缩放, 50-%u ms)\n"
       "  -m megs       - 子进程内存限制 (%u MB)\n"
       "  -Q            - 使用二进制插桩 (QEMU模式)\n\n"     
 
       "模糊行为设置:\n\n"

       "  -d            - 快速模式 (跳过确定性步骤)\n"
       "  -n            - 无插桩模糊 (笨拙模式)\n"
       "  -x dir        - 可选的模糊字典 (见README)\n\n"

       "其他:\n\n"

       "  -T text       - 在屏幕上显示的文本横幅\n"
       "  -M / -S id    - 分布式模式 (见parallel_fuzzing.txt)\n"
       "  -C            - 崩溃探索模式 (peruvian rabbit thing)\n"
       "  -V            - 显示版本号并退出\n\n"
       "  -b cpu_id     - 将模糊进程绑定到指定的CPU核心\n\n"

       "📝 此版本使用模块化架构，代码已重构为多个专业模块\n"
       "📂 架构: core/ utils/ analysis/ io/ main/\n"
       "有关其他提示，请查阅 %s/README。\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);
}

/* 制作当前命令行的副本 */
void save_cmdline(u32 argc, char** argv) {
  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;
  
  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++) {
    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';
  }

  *buf = 0;
}

/* 为QEMU重写argv */
char** get_qemu_argv(u8* own_loc, char** argv, int argc) {
  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  /* QEMU稳定性故障的变通方法 */
  setenv("QEMU_LOG", "nochain", 1);

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* 现在我们需要实际找到要放在argv[0]中的QEMU二进制文件 */
  tmp = getenv("AFL_PATH");

  if (tmp) {
    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;
  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {
    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {
      target_path = new_argv[0] = cp;
      return new_argv;
    }

  } else ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {
    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;
  }

  SAYF("\n" cLRD "[-] " cRST
       "糟糕，找不到'afl-qemu-trace'二进制文件。该二进制文件必须按照qemu_mode/README.qemu中的说明单独构建。\n"
       "    如果您已经安装了二进制文件，可能需要在环境中指定AFL_PATH。\n\n"

       "    当然，即使没有QEMU，afl-fuzz仍然可以与在编译时用afl-gcc插桩的二进制文件一起工作。\n"
       "    还可以通过在命令行中指定'-n'将其用作传统的笨拙模糊器。\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");
}

#ifndef AFL_LIB

/* 主入口点 */
int main(int argc, char** argv) {
  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8  *extras_dir = 0;
  u8  mem_limit_given = 0;
  u8  exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  char** use_argv;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  /* 解析命令行参数 */
  while ((opt = getopt(argc, argv, "+i:o:f:m:b:t:T:dnCB:S:M:x:QV")) > 0)

    switch (opt) {

      case 'i': /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M': { /* master sync ID */

          u8* c;

          if (sync_id) FATAL("Multiple -S or -M options not supported");
          sync_id = ck_strdup(optarg);

          if ((c = strchr(sync_id, ':'))) {

            *c = 0;

            if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
                !master_id || !master_max || master_id > master_max ||
                master_max > 1000000) FATAL("Bogus master ID passed to -M");

          }

          force_deterministic = 1;

        }

        break;

      case 'S': 

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 't': { /* timeout */

          u8 suffix = 0;

          if (timeout_given) FATAL("Multiple -t options not supported");

          if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -t");

          if (exec_tmout < 5) FATAL("Dangerously low value of -t");

          if (suffix == '+') timeout_given = 2; else timeout_given = 1;

          break;

      }

      case 'm': { /* mem limit */

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;
      
      case 'b': { /* bind CPU core */

          if (cpu_to_bind_given) FATAL("Multiple -b options not supported");
          cpu_to_bind_given = 1;

          if (sscanf(optarg, "%u", &cpu_to_bind) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -b");

          break;

      }

      case 'd': /* skip deterministic */

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'n': /* dumb mode */

        if (dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV")) dumb_mode = 2; else dumb_mode = 1;

        break;

      case 'T': /* banner */

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      case 'Q': /* QEMU mode */

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        break;

      case 'V': /* Show version number */

        /* Version number has been printed already, just quit. */
        exit(0);

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  save_cmdline(argc, argv);

  /* 同步模式验证 */
  if (sync_id) fix_up_sync();

  /* 检查目录 */
  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if (dumb_mode) {
    if (qemu_mode) FATAL("-Q and -n are mutually exclusive");
  }

  /* 环境变量检查 */
  if (getenv("AFL_NO_FORKSRV"))    no_forkserver    = 1;
  if (getenv("AFL_NO_CPU_RED"))    no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH"))      no_arith         = 1;
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue    = 1;
  if (getenv("AFL_FAST_CAL"))      fast_cal         = 1;

  if (getenv("AFL_HANG_TMOUT")) {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");
  }

  /* 设置横幅 */
  fix_up_banner(argv[optind]);

  /* 检查TTY */  
  check_if_tty();

  /* 获取CPU核心数 */
  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  /* 初始化核心组件 */
  init_count_class16();
  
  /* 读取测试用例 */
  read_testcases();
  
  start_time = get_cur_time();
  
  /* 基本的主循环逻辑 */
  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  /* 查找开始位置（恢复模式） */
  seek_to = find_start_position();

  /* 写入初始统计文件 */
  write_stats_file(0, 0, 0);
  
  if (stop_soon) goto stop_fuzzing;

  SAYF("模块化AFL初始化完成。\n");
  SAYF("输入目录: %s\n", in_dir);
  SAYF("输出目录: %s\n", out_dir);
  SAYF("总测试用例: %u\n", queued_paths);
  
  /* 简化的主模糊循环 */
  while (1) {
    
    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {

      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {
        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;
      }

      show_stats();

      if (not_on_tty) {
        ACTF("进入队列循环 %llu。", queue_cycle);
        fflush(stdout);
      }

      if (queued_paths == prev_queued) {
        if (use_splicing) cycles_wo_finds++; else use_splicing = 1;
      } else cycles_wo_finds = 0;

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(use_argv);

    }

    skipped_fuzz = fuzz_one(use_argv);

    if (!stop_soon && sync_id && !skipped_fuzz) {
      if (!(sync_interval_cnt++ % SYNC_INTERVAL))
        sync_fuzzers(use_argv);
    }

    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    current_entry++;
  }

  if (queue_cur) show_stats();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ 测试已终止 +++\n" cRST);

  /* 运行超过30分钟但仍在做第一轮？ */
  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {
    SAYF("\n" cYEL "[!] " cRST
           "在第一轮期间停止，结果可能不完整。\n"
           "    （有关恢复的信息，请参阅 %s/README。）\n", doc_path);
  }

  destroy_queue();
  
  SAYF("完成！祝您愉快！\n");

  exit(0);
}

#endif /* !AFL_LIB */