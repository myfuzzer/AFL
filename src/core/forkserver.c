/*
   american fuzzy lop - 分叉服务器模块实现
   ====================================

   实现分叉服务器功能，用于优化执行性能
*/

#include "forkserver.h"
#include "../utils/timing.h"

#define ASAN_MIN_MEM 50  /* ASAN 最小内存限制 (MB) */

extern u8* trace_bits;
extern u8* target_path;
extern u32 exec_tmout;
extern u64 mem_limit;
extern s32 dev_null_fd, out_fd, fsrv_ctl_fd, fsrv_st_fd, out_dir_fd, dev_urandom_fd;
extern u8* out_file;
extern s32 forksrv_pid;
extern volatile u8 child_timed_out;
extern FILE* plot_file;

/* 启动分叉服务器（仅插桩模式）。这个想法在这里解释：

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   实质上，插桩允许我们跳过execve()，只是保持克隆一个停止的子进程。
   所以，我们只执行一次，然后通过管道发送命令。这个逻辑的另一部分在afl-as.h中 */

void init_forkserver(char** argv) {

  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("启动分叉服务器...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() 失败");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() 失败");

  if (!forksrv_pid) {

    struct rlimit r;

    /* 在OpenBSD上，root用户的默认fd限制设置为软128。让我们试着修复它... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* 忽略错误 */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* 忽略错误 */

#else

      /* 这照顾了OpenBSD，它没有RLIMIT_AS，但根据可靠的消息来源，
         RLIMIT_DATA覆盖匿名映射 - 所以我们应该得到良好的保护，防止OOM错误 */

      setrlimit(RLIMIT_DATA, &r); /* 忽略错误 */

#endif /* ^RLIMIT_AS */


    }

    /* 转储核心是慢的，如果SIGKILL在转储完成之前交付，可能导致异常 */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* 忽略错误 */

    /* 隔离进程并配置标准描述符。如果指定了out_file，则stdin是/dev/null；
       否则，out_fd被克隆 */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* 设置控制和状态管道，关闭不需要的原始fd */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() 失败");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() 失败");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* 这应该稍微提高性能，因为它阻止链接器在fork()后做额外的工作 */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* 如果没有指定其他内容，为ASAN设置合理的默认值 */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN很棘手，因为它在这一点上不支持abort_on_error=1。
       所以，我们以一种非常hacky的方式来做这件事 */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* 使用独特的位图签名来告诉父进程execv()失败 */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* 关闭不需要的端点 */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* 等待分叉服务器启动，但不要等太久 */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* 如果我们从服务器收到四字节的"hello"消息，我们都设置好了。
     否则，试图弄清楚出了什么问题 */

  if (rlen == 4) {
    OKF("好的 - 分叉服务器已启动。");
    return;
  }

  if (child_timed_out)
    FATAL("初始化分叉服务器时超时（调整-t可能有帮助）");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() 失败");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "哎呀，目标二进制文件突然崩溃，在从模糊器接收任何输入之前！\n"
           "    由于它似乎是用ASAN构建的，并且您配置了限制性内存限制，\n"
           "    这是预期的；请阅读 %s/notes_for_asan.txt 获取帮助。\n", doc_path);

    } else if (!mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "哎呀，目标二进制文件突然崩溃，在从模糊器接收任何输入之前！\n"
           "    有几种可能的解释：\n\n"

           "    - 二进制文件只是有问题，完全自己爆炸。如果是这样，您需要\n"
           "      修复潜在问题或找到更好的替代品。\n\n"

#ifdef __APPLE__

           "    - 在MacOS X上，fork()系统调用的语义是非标准的，在运行\n"
           "      平台特定目标时可能会破坏afl-fuzz性能优化。要修复此问题，\n"
           "      请在环境中设置AFL_NO_FORKSRV=1。\n\n"

#endif /* __APPLE__ */

           "    - 不太可能的是，模糊器中有一个可怕的错误。如果其他选项\n"
           "      失败，请联系 <lcamtuf@coredump.cx> 获取故障排除提示。\n");

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "哎呀，目标二进制文件突然崩溃，在从模糊器接收任何输入之前！\n"
           "    有几种可能的解释：\n\n"

           "    - 当前内存限制（%s）过于限制，导致目标\n"
           "      在初始化期间崩溃。尝试将其提高到25 MB或更多。\n\n"

           "    - 二进制文件只是有问题，完全自己爆炸。如果是这样，您需要\n"
           "      修复潜在问题或找到更好的替代品。\n\n"

           "    - 不太可能的是，模糊器中有一个可怕的错误。如果其他选项\n"
           "      失败，请联系 <lcamtuf@coredump.cx> 获取故障排除提示。\n",
           DMS(mem_limit << 20)); /* 忽略错误 */

    }

    FATAL("分叉服务器崩溃，退出码%d", WEXITSTATUS(status));

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("无法执行目标应用程序（'%s'）", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
         "哎呀，看起来二进制文件是用ASAN编译的，但您有一个非常紧的\n"
         "    内存限制设置（%s）。这可能完全导致崩溃，即使没有任何错误\n"
         "    在测试的代码中。\n\n"

         "    要修复此问题，请将-m设置为至少%u，或考虑重新编译\n"
         "    没有ASAN的程序。\n", DMS(mem_limit << 20), ASAN_MIN_MEM);

    FATAL("ASAN内存限制太低");

  }

  OKF("一切正常，已准备开始模糊测试。");

}