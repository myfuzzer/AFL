/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef AFL_GLOBALS_H
#define AFL_GLOBALS_H

#include "../../config.h"
#include "../../types.h"
#include "../../debug.h"
#include "../../alloc-inl.h" 
#include "../../hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <termios.h>
#include <dlfcn.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>
#endif

#ifdef __linux__
#  define HAVE_AFFINITY 1
#endif

#ifdef AFL_LIB
#  define EXP_ST
#else
#  define EXP_ST static
#endif

/* 测试用例队列条目结构 */
struct queue_entry {
  u8* fname;                          /* 测试用例文件名 */
  u32 len;                            /* 输入长度 */

  u8  cal_failed,                     /* 校准失败？ */
      trim_done,                      /* 已精简？ */
      was_fuzzed,                     /* 已经进行过fuzz测试？ */
      passed_det,                     /* 通过确定性测试？ */
      has_new_cov,                    /* 触发新覆盖率？ */
      var_behavior,                   /* 可变行为？ */
      favored,                        /* 当前偏爱的？ */
      fs_redundant;                   /* 在文件系统中标记为冗余？ */

  u32 bitmap_size,                    /* 位图中设置的位数 */
      exec_cksum;                     /* 执行轨迹的校验和 */

  u64 exec_us,                        /* 执行时间（微秒） */
      handicap,                       /* 队列周期数量落后 */
      depth;                          /* 路径深度 */

  u32 exec_speed;                     /* 执行速度（超时值） */

  u8* trace_mini;                     /* 轨迹字节，如果保留 */
  u32 tc_ref;                         /* 轨迹字节引用计数 */

  struct queue_entry *next,           /* 下一个元素，如果有的话 */
                     *next_100;       /* 100个元素之前 */
};

/* 额外数据结构（字典条目） */
struct extra_data {
  u8* data;                           /* 字典token数据 */
  u32 len;                            /* 字典token长度 */
  u32 hit_cnt;                        /* 在语料库中的使用计数 */
};

/* 模糊测试阶段枚举 */
enum {
  STAGE_FLIP1,
  STAGE_FLIP2,
  STAGE_FLIP4,
  STAGE_FLIP8,
  STAGE_FLIP16,
  STAGE_FLIP32,
  STAGE_ARITH8,
  STAGE_ARITH16,
  STAGE_ARITH32,
  STAGE_INTEREST8,
  STAGE_INTEREST16,
  STAGE_INTEREST32,
  STAGE_EXTRAS_UO,
  STAGE_EXTRAS_UI,
  STAGE_EXTRAS_AO,
  STAGE_HAVOC,
  STAGE_SPLICE
};

/* 阶段值类型枚举 */
enum {
  STAGE_VAL_NONE,
  STAGE_VAL_LE,
  STAGE_VAL_BE
};

/* 执行状态故障代码 */
enum {
  FAULT_NONE,
  FAULT_TMOUT,
  FAULT_CRASH,
  FAULT_ERROR,
  FAULT_NOINST,
  FAULT_NOBITS
};

/* 全局变量声明 */

/* 输入输出目录和文件路径 */
extern u8 *in_dir,                    /* 包含测试用例的输入目录 */
          *out_file,                  /* 要fuzz的文件，如果有的话 */
          *out_dir,                   /* 工作和输出目录 */
          *sync_dir,                  /* 同步目录 */
          *sync_id,                   /* 模糊器ID */
          *use_banner,                /* 显示横幅 */
          *in_bitmap,                 /* 输入位图 */
          *doc_path,                  /* 文档目录路径 */
          *target_path,               /* 目标二进制路径 */
          *orig_cmdline;              /* 原始命令行 */

/* 超时和内存限制 */
extern u32 exec_tmout;                /* 可配置的执行超时（毫秒） */
extern u64 mem_limit;                 /* 子进程内存上限（MB） */
extern u32 cpu_to_bind;               /* 绑定到的空闲CPU核心ID */

/* 控制标志 */
extern u8  skip_deterministic,        /* 跳过确定性阶段？ */
           force_deterministic,       /* 强制确定性阶段？ */
           use_splicing,              /* 重组输入文件？ */
           dumb_mode,                 /* 在非插桩模式下运行？ */
           score_changed,             /* 收藏夹评分改变？ */
           kill_signal,               /* 杀死子进程的信号 */
           resuming_fuzz,             /* 恢复较旧的fuzz作业？ */
           timeout_given,             /* 给定特定超时？ */
           cpu_to_bind_given,         /* 指定cpu_to_bind给定？ */
           not_on_tty,                /* stdout不是tty */
           term_too_small,            /* 终端尺寸太小 */
           uses_asan,                 /* 目标使用ASAN？ */
           no_forkserver,             /* 禁用forkserver？ */
           crash_mode,                /* 崩溃模式！Yeah！ */
           in_place_resume,           /* 尝试就地恢复？ */
           auto_changed,              /* 自动生成的token改变？ */
           no_cpu_meter_red,          /* 状态屏幕上的风水 */
           no_arith,                  /* 跳过大多数算术操作 */
           shuffle_queue,             /* 打乱输入队列？ */
           bitmap_changed,            /* 更新位图的时间？ */
           qemu_mode,                 /* 在QEMU模式下运行？ */
           skip_requested,            /* 跳过请求，通过SIGUSR1 */
           run_over10m,               /* 运行时间超过10分钟？ */
           persistent_mode,           /* 在持久模式下运行？ */
           deferred_mode,             /* 延迟forkserver模式？ */
           fast_cal;                  /* 尝试更快校准？ */

/* 文件描述符 */
extern s32 out_fd,                    /* out_file的持久fd */
           dev_urandom_fd,            /* /dev/urandom的持久fd */
           dev_null_fd,               /* /dev/null的持久fd */
           fsrv_ctl_fd,               /* Fork服务器控制管道（写） */
           fsrv_st_fd,                /* Fork服务器状态管道（读） */
           forksrv_pid,               /* fork服务器的PID */
           child_pid,                 /* 被fuzz程序的PID */
           out_dir_fd;                /* 锁文件的FD */

/* 共享内存和位图 */
extern u8* trace_bits;                /* 带有插桩位图的SHM */
extern u8  virgin_bits[MAP_SIZE],     /* 尚未被fuzz触及的区域 */
           virgin_tmout[MAP_SIZE],    /* 我们在超时中没有看到的位 */
           virgin_crash[MAP_SIZE];    /* 我们在崩溃中没有看到的位 */

/* 统计计数器 */
extern u32 queued_paths,              /* 排队的测试用例总数 */
           queued_variable,           /* 具有可变行为的测试用例 */
           queued_at_start,           /* 初始输入总数 */
           queued_discovered,         /* 此次运行中发现的条目 */
           queued_imported,           /* 通过-S导入的条目 */
           queued_favored,            /* 被认为有利的路径 */
           queued_with_cov,           /* 有新覆盖率字节的路径 */
           pending_not_fuzzed,        /* 排队但尚未完成 */
           pending_favored,           /* 待处理的偏爱路径 */
           cur_skipped_paths,         /* 当前周期中放弃的输入 */
           cur_depth,                 /* 当前路径深度 */
           max_depth,                 /* 最大路径深度 */
           useless_at_start,          /* 无用起始路径数量 */
           var_byte_count,            /* 具有var行为的位图字节 */
           current_entry,             /* 当前队列条目ID */
           havoc_div;                 /* havoc的周期计数除数 */

extern u64 total_crashes,             /* 崩溃总数 */
           unique_crashes,            /* 具有唯一签名的崩溃 */
           total_tmouts,              /* 超时总数 */
           unique_tmouts,             /* 具有唯一签名的超时 */
           unique_hangs,              /* 具有唯一签名的挂起 */
           total_execs,               /* 总execve()调用 */
           slowest_exec_ms,           /* 最慢的非挂起测试用例（毫秒） */
           start_time,                /* Unix开始时间（毫秒） */
           last_path_time,            /* 最近路径的时间（毫秒） */
           last_crash_time,           /* 最近崩溃的时间（毫秒） */
           last_hang_time,            /* 最近挂起的时间（毫秒） */
           last_crash_execs,          /* 最后崩溃时的执行计数器 */
           queue_cycle,               /* 队列轮次计数器 */
           cycles_wo_finds,           /* 没有新路径的周期 */
           trim_execs,                /* 为修剪输入文件而执行的execve */
           bytes_trim_in,             /* 进入修剪器的字节 */
           bytes_trim_out,            /* 从修剪器出来的字节 */
           blocks_eff_total,          /* 受效应器映射影响的块 */
           blocks_eff_select;         /* 选择为可fuzz的块 */

/* 阶段信息 */
extern u8 *stage_name,                /* 当前fuzz阶段的名称 */
          *stage_short,               /* 简短阶段名称 */
          *syncing_party;             /* 当前正在同步的... */

extern s32 stage_cur, stage_max;      /* 阶段进度 */
extern s32 splicing_with;             /* 与哪个测试用例拼接？ */

extern u32 master_id, master_max;     /* 主实例作业分割 */
extern u32 syncing_case;              /* 与案例#...同步 */

extern s32 stage_cur_byte,            /* 当前阶段操作的字节偏移 */
           stage_cur_val;             /* 用于阶段操作的值 */

extern u8  stage_val_type;            /* 值类型（STAGE_VAL_*） */

extern u64 stage_finds[32],           /* 每个fuzz阶段发现的模式 */
           stage_cycles[32];          /* 每个fuzz阶段的执行 */

/* 队列和评级 */
extern struct queue_entry *queue,     /* Fuzz队列（链表） */
                          *queue_cur, /* 队列中的当前偏移 */
                          *queue_top, /* 列表顶部 */
                          *q_prev100; /* 前100个标记 */

extern struct queue_entry* top_rated[MAP_SIZE]; /* 位图字节的顶级条目 */

/* 字典和额外数据 */
extern struct extra_data* extras;     /* 用于fuzz的额外token */
extern u32 extras_cnt;                /* 读取的token总数 */

extern struct extra_data* a_extras;   /* 自动选择的额外项 */
extern u32 a_extras_cnt;              /* 可用token总数 */

/* 后处理处理程序 */
extern u8* (*post_handler)(u8* buf, u32* len);

/* 有趣的值 */
extern s8  interesting_8[9];
extern s16 interesting_16[9 + 10];
extern s32 interesting_32[9 + 10 + 8];

/* CPU核心计数和亲和性 */
extern s32 cpu_core_count;            /* CPU核心计数 */

#ifdef HAVE_AFFINITY
extern s32 cpu_aff;                   /* 选择的CPU核心 */
#endif

/* 输出文件 */
extern FILE* plot_file;               /* Gnuplot输出文件 */

/* 随机数生成 */
extern u32 rand_cnt;                  /* 随机数计数器 */

/* 校准统计 */
extern u64 total_cal_us,              /* 总校准时间（微秒） */
           total_cal_cycles;          /* 总校准周期 */

/* 位图统计 */
extern u64 total_bitmap_size,         /* 所有位图的总位数 */
           total_bitmap_entries;      /* 计数的位图数量 */

/* 控制变量 */
extern volatile u8 stop_soon,         /* 按了Ctrl-C？ */
                   clear_screen,      /* 窗口大小调整？ */
                   child_timed_out;   /* 跟踪进程超时？ */

/* 统计更新频率 */
extern u32 stats_update_freq;         /* 统计更新频率（执行数） */

/* 超时相关 */
extern u32 hang_tmout;                /* 用于挂起检测的超时（毫秒） */
extern u32 subseq_tmouts;             /* 连续超时数 */

/* 可变字节数组 */
extern u8 var_bytes[MAP_SIZE];        /* 看起来可变的字节 */

/* 共享内存ID */
extern s32 shm_id;                    /* SHM区域的ID */

/* 缺失的常量定义 */
#ifndef MAX_AUTO_EXTRA
#define MAX_AUTO_EXTRA      50
#endif

#ifndef USE_AUTO_EXTRAS  
#define USE_AUTO_EXTRAS     50
#endif

#ifndef SYNC_INTERVAL
#define SYNC_INTERVAL       5
#endif

/* 额外的全局变量 */
extern u8  first_run;              /* 首次运行标志 */
extern u32 ret_val;                /* 返回值 */

/* 全局函数声明 */
void init_globals(void);
void cleanup_globals(void);
void setup_shm(void);

/* 辅助函数声明 */
void shuffle_ptrs(void** ptrs, u32 cnt);
u32 hash32(const void* key, u32 len, u32 seed);
void find_timeout(void);

#endif /* AFL_GLOBALS_H */