/*
   american fuzzy lop - 执行器模块实现
   ==================================

   实现目标程序执行和监控功能
*/

#include "executor.h"
#include "../utils/timing.h"
#include "../analysis/bitmap.h"
#include "queue.h"

extern u8* trace_bits;
extern u8* out_file;
extern u32 exec_tmout;
extern u64 mem_limit;
extern s32 out_fd, dev_null_fd, fsrv_ctl_fd, fsrv_st_fd;
extern volatile u8 child_timed_out;
extern u8 dumb_mode, no_forkserver;
extern volatile u8 stop_soon;
extern u64 total_execs, slowest_exec_ms, total_cal_us, total_cal_cycles;
extern u8 crash_mode;
extern s32 forksrv_pid, child_pid;
extern u8 kill_signal;
extern u8* target_path;
extern u8 fast_cal;
extern u32 queued_paths, queued_with_cov, queued_variable;
extern u64 unique_crashes;
extern u8 virgin_bits[MAP_SIZE], var_bytes[MAP_SIZE];

/* 前向声明 */
void init_forkserver(char** argv);
void show_stats(void);
u8 has_new_bits(u8* virgin_map);
extern u32 var_byte_count;
extern u64 total_bitmap_size, total_bitmap_entries;
extern u8* stage_name;
extern s32 stage_cur, stage_max;
extern u32 stats_update_freq;

/* 执行目标应用程序，监控超时。成功返回0，超时返回1，
   崩溃返回2。核心函数 - 执行实际模糊测试运行 */
u8 run_target(char** argv, u32 timeout) {
  static struct itimerval it;
  static u32 prev_timed_out = 0;
  static u64 exec_ms = 0;

  int status = 0;
  u32 tb4;
  s32 res;

  child_timed_out = 0;

  /* 在无分支服务器模式下，我们每次调用execve()。这是一个相当慢的操作，
     但可以让我们处理各种非标准目标 */

  if (dumb_mode == 1 || no_forkserver) {

    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() 失败");

    if (!child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS
        setrlimit(RLIMIT_AS, &r); /* 忽略错误 */
#else
        setrlimit(RLIMIT_DATA, &r); /* 忽略错误 */
#endif /* ^RLIMIT_AS */

      }

      /* 防止核心转储是慢的 */
      r.rlim_max = r.rlim_cur = 0;
      setrlimit(RLIMIT_CORE, &r); /* 忽略错误 */

      /* 隔离进程并配置标准描述符 */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {
        dup2(dev_null_fd, 0);
      } else {
        dup2(out_fd, 0);
        close(out_fd);
      }

      /* 设置环境变量 */
      if (getenv("AFL_PRELOAD")) {
        setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
        setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
      }

      execv(target_path, argv);

      /* 使用特定的退出代码 */
      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }

  } else {

    /* 在分叉服务器模式下，我们只需要告诉它创建一个新进程... */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4)
      FATAL("无法请求新进程");

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4)
      FATAL("无法请求新进程");

    if (child_pid <= 0) FATAL("Fork server故障");

  }

  /* 设置超时。使用setitimer()而不是alarm()，因为前者对子进程是透明的 */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* 等待子进程终止 */

  if (dumb_mode == 1 || no_forkserver) {

    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() 失败");

  } else {

    if ((res = read(fsrv_st_fd, &status, 4)) != 4)
      FATAL("无法从分叉服务器接收()");

  }

  if (!WIFSTOPPED(status)) child_pid = 0;

  getitimer(ITIMER_REAL, &it);
  exec_ms = (u64) timeout - (it.it_value.tv_sec * 1000 +
                            it.it_value.tv_usec / 1000);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* 任何后续计时 */

  if (slowest_exec_ms < exec_ms) slowest_exec_ms = exec_ms;

  /* 报告结果 */

  if (WIFSIGNALED(status) && !stop_soon) {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }

  /* 一个不太常见的例子：我们在子进程正在运行时捕获了^C；它必须是手动停止的 */

  if (stop_soon && !child_timed_out) {
    child_timed_out = 1;
    if (child_pid > 0) kill(child_pid, SIGKILL);
  }

  if (child_timed_out) return FAULT_TMOUT;

  /* 检查执行失败 */

  tb4 = *(u32*)trace_bits;

  if (!dumb_mode && tb4 == EXEC_FAIL_SIG) return FAULT_ERROR;

  return FAULT_NONE;

}

/* 将修改后的数据写入临时文件，然后被被测程序读取。如果out_file被设置，
   那个临时文件被使用。否则，数据通过stdin传递 */
void write_to_testcase(void* mem, u32 len) {
  
  s32 fd = out_fd;

  if (out_file) {
    
    unlink(out_file); /* 忽略错误 */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("无法创建'%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() 失败");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}

/* 执行单一执行，处理故障恢复的超时等等。我们需要参数列表，内存块和长度作为参数。
   这是core_fuzzing_loop调用的例程 */
u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                 u32 handicap, u8 from_queue) {

  u8  fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
      first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = stage_name;

  /* 务必定时这个最初的运行 */

  stage_name = "校准";
  stage_max  = fast_cal ? 3 : 8;

  start_us = get_cur_time_us();

  /* 确保分叉服务器正在运行，如果这是我们的第一个真正的测试案例 */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);

  if (q->exec_speed) use_tmout = q->exec_speed;

  /* 运行真实的校准循环 */

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

    write_to_testcase(use_mem, q->len);

    fault = run_target(argv, use_tmout);

    /* stop_soon被其他线程设置 */
    if (stop_soon || fault != crash_mode) goto abort_calibration;

    if (!dumb_mode && (first_run || new_bits)) {

      cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (first_run) q->exec_cksum = cksum;
      else if (q->exec_cksum != cksum) var_detected = 1;

      hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

    }

  }

  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* 成功！ */

  if (var_detected) {

    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior) {
      mark_as_variable(q);
      queued_variable++;
    }

  }

  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

  /* 如果这个路径不计算对我们有价值的新覆盖，让我们标记它as redundant */

  if (!dumb_mode && first_run && !fault && !new_bits) mark_as_redundant(q, !q->favored);

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* 将事情标记为正常 */

  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;

  if (!first_run) show_stats();

  return fault;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  q->cal_failed = fault;
  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;

  return fault;

}