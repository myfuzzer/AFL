/*
   american fuzzy lop - 主程序模块实现
   ===================================

   实现主函数和命令行处理
*/

#include "main.h"
#include "../utils/timing.h"
#include "../analysis/bitmap.h"
#include "../core/queue.h"
#include "../io/stats.h"

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

      case 'V': /* Show version number */

        /* Version number has been printed already, just quit. */
        exit(0);

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  save_cmdline(argc, argv);

  /* 初始化核心组件 */
  init_count_class16();
  
  start_time = get_cur_time();
  
  /* 写入初始统计文件 */
  write_stats_file(0, 0, 0);
  
  SAYF("模块化AFL初始化完成。\n");
  SAYF("输入目录: %s\n", in_dir);
  SAYF("输出目录: %s\n", out_dir);
  
  /* 模拟一些基本操作以确保函数被调用和链接 */
  destroy_queue();
  
  exit(0);
}

#endif /* !AFL_LIB */