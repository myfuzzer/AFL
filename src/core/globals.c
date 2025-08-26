/*
   american fuzzy lop - 全局变量定义
   =================================

   定义所有全局变量的实际存储
*/

#include "globals.h"

/* 输入输出目录和文件路径 */
u8 *in_dir,                           /* 包含测试用例的输入目录 */
   *out_file,                         /* 要fuzz的文件，如果有的话 */
   *out_dir,                          /* 工作和输出目录 */
   *sync_dir,                         /* 同步目录 */
   *sync_id,                          /* 模糊器ID */
   *use_banner,                       /* 显示横幅 */
   *in_bitmap,                        /* 输入位图 */
   *doc_path,                         /* 文档目录路径 */
   *target_path,                      /* 目标二进制路径 */
   *orig_cmdline;                     /* 原始命令行 */

/* 超时和内存限制 */
u32 exec_tmout = EXEC_TIMEOUT;        /* 可配置的执行超时（毫秒） */
u32 hang_tmout = EXEC_TIMEOUT; /* 用于挂起检测的超时（毫秒） */
u64 mem_limit = MEM_LIMIT;            /* 子进程内存上限（MB） */
u32 cpu_to_bind = 0;                  /* 绑定到的空闲CPU核心ID */

u32 stats_update_freq = 1;     /* 统计更新频率（执行数） */

/* 控制标志 */
u8  skip_deterministic,               /* 跳过确定性阶段？ */
    force_deterministic,              /* 强制确定性阶段？ */
    use_splicing,                     /* 重组输入文件？ */
    dumb_mode,                        /* 在非插桩模式下运行？ */
    score_changed,                    /* 收藏夹评分改变？ */
    kill_signal,                      /* 杀死子进程的信号 */
    resuming_fuzz,                    /* 恢复较旧的fuzz作业？ */
    timeout_given,                    /* 给定特定超时？ */
    cpu_to_bind_given,                /* 指定cpu_to_bind给定？ */
    not_on_tty,                       /* stdout不是tty */
    term_too_small,                   /* 终端尺寸太小 */
    uses_asan,                        /* 目标使用ASAN？ */
    no_forkserver,                    /* 禁用forkserver？ */
    crash_mode,                       /* 崩溃模式！Yeah！ */
    in_place_resume,                  /* 尝试就地恢复？ */
    auto_changed,                     /* 自动生成的token改变？ */
    no_cpu_meter_red,                 /* 状态屏幕上的风水 */
    no_arith,                         /* 跳过大多数算术操作 */
    shuffle_queue,                    /* 打乱输入队列？ */
    bitmap_changed = 1,               /* 更新位图的时间？ */
    qemu_mode,                        /* 在QEMU模式下运行？ */
    skip_requested,                   /* 跳过请求，通过SIGUSR1 */
    run_over10m,                      /* 运行时间超过10分钟？ */
    persistent_mode,                  /* 在持久模式下运行？ */
    deferred_mode,                    /* 延迟forkserver模式？ */
    fast_cal;                         /* 尝试更快校准？ */

/* 文件描述符 */
s32 out_fd,                    /* out_file的持久fd */
    dev_urandom_fd = -1,       /* /dev/urandom的持久fd */
    dev_null_fd = -1,          /* /dev/null的持久fd */
    fsrv_ctl_fd,               /* Fork服务器控制管道（写） */
    fsrv_st_fd;                /* Fork服务器状态管道（读） */

s32 forksrv_pid,               /* fork服务器的PID */
    child_pid = -1,            /* 被fuzz程序的PID */
    out_dir_fd = -1;           /* 锁文件的FD */

/* 共享内存和位图 */
u8* trace_bits;                       /* 带有插桩位图的SHM */

u8  virgin_bits[MAP_SIZE],            /* 尚未被fuzz触及的区域 */
    virgin_tmout[MAP_SIZE],           /* 我们在超时中没有看到的位 */
    virgin_crash[MAP_SIZE];           /* 我们在崩溃中没有看到的位 */

u8  var_bytes[MAP_SIZE];       /* 看起来可变的字节 */

s32 shm_id;                    /* SHM区域的ID */

/* 控制变量 */
volatile u8 stop_soon,         /* 按了Ctrl-C？ */
            clear_screen = 1,  /* 窗口大小调整？ */
            child_timed_out;   /* 跟踪进程超时？ */

/* 统计计数器 */
u32 queued_paths,                     /* 排队的测试用例总数 */
    queued_variable,                  /* 具有可变行为的测试用例 */
    queued_at_start,                  /* 初始输入总数 */
    queued_discovered,                /* 此次运行中发现的条目 */
    queued_imported,                  /* 通过-S导入的条目 */
    queued_favored,                   /* 被认为有利的路径 */
    queued_with_cov,                  /* 有新覆盖率字节的路径 */
    pending_not_fuzzed,               /* 排队但尚未完成 */
    pending_favored,                  /* 待处理的偏爱路径 */
    cur_skipped_paths,                /* 当前周期中放弃的输入 */
    cur_depth,                        /* 当前路径深度 */
    max_depth,                        /* 最大路径深度 */
    useless_at_start,                 /* 无用起始路径数量 */
    var_byte_count,                   /* 具有var行为的位图字节 */
    current_entry,                    /* 当前队列条目ID */
    havoc_div = 1;                    /* havoc的周期计数除数 */

u64 total_crashes,                    /* 崩溃总数 */
    unique_crashes,                   /* 具有唯一签名的崩溃 */
    total_tmouts,                     /* 超时总数 */
    unique_tmouts,                    /* 具有唯一签名的超时 */
    unique_hangs,                     /* 具有唯一签名的挂起 */
    total_execs,                      /* 总execve()调用 */
    slowest_exec_ms,                  /* 最慢的非挂起测试用例（毫秒） */
    start_time,                       /* Unix开始时间（毫秒） */
    last_path_time,                   /* 最近路径的时间（毫秒） */
    last_crash_time,                  /* 最近崩溃的时间（毫秒） */
    last_hang_time,                   /* 最近挂起的时间（毫秒） */
    last_crash_execs,                 /* 最后崩溃时的执行计数器 */
    queue_cycle,                      /* 队列轮次计数器 */
    cycles_wo_finds,                  /* 没有新路径的周期 */
    trim_execs,                       /* 为修剪输入文件而执行的execve */
    bytes_trim_in,                    /* 进入修剪器的字节 */
    bytes_trim_out,                   /* 从修剪器出来的字节 */
    blocks_eff_total,                 /* 受效应器映射影响的块 */
    blocks_eff_select;                /* 选择为可fuzz的块 */

u32 subseq_tmouts;             /* 连续超时数 */

/* 阶段信息 */
u8 *stage_name = "init",       /* 当前fuzz阶段的名称 */
          *stage_short,               /* 简短阶段名称 */
          *syncing_party;             /* 当前正在同步的... */

s32 stage_cur, stage_max;      /* 阶段进度 */
s32 splicing_with = -1;        /* 与哪个测试用例拼接？ */

u32 master_id, master_max;     /* 主实例作业分割 */
u32 syncing_case;              /* 与案例#...同步 */

s32 stage_cur_byte,            /* 当前阶段操作的字节偏移 */
           stage_cur_val;             /* 用于阶段操作的值 */

u8 stage_val_type;            /* 值类型（STAGE_VAL_*） */

u64 stage_finds[32],           /* 每个fuzz阶段发现的模式 */
           stage_cycles[32];          /* 每个fuzz阶段的执行 */

/* 随机数生成 */
u32 rand_cnt;                  /* 随机数计数器 */

/* 校准统计 */
u64 total_cal_us,              /* 总校准时间（微秒） */
           total_cal_cycles;          /* 总校准周期 */

/* 位图统计 */
u64 total_bitmap_size,         /* 所有位图的总位数 */
           total_bitmap_entries;      /* 计数的位图数量 */

/* CPU核心计数和亲和性 */
s32 cpu_core_count;            /* CPU核心计数 */

#ifdef HAVE_AFFINITY
s32 cpu_aff = -1;              /* 选择的CPU核心 */
#endif

/* 输出文件 */
FILE* plot_file;               /* Gnuplot输出文件 */

/* 队列和评级 */
struct queue_entry *queue,     /* Fuzz队列（链表） */
                          *queue_cur, /* 队列中的当前偏移 */
                          *queue_top, /* 列表顶部 */
                          *q_prev100; /* 前100个标记 */

struct queue_entry* top_rated[MAP_SIZE]; /* 位图字节的顶级条目 */

/* 字典和额外数据 */
struct extra_data* extras;     /* 用于fuzz的额外token */
u32 extras_cnt;                /* 读取的token总数 */

struct extra_data* a_extras;   /* 自动选择的额外项 */
u32 a_extras_cnt;              /* 可用token总数 */

/* 后处理处理程序 */
u8* (*post_handler)(u8* buf, u32* len);

/* 有趣的值 */
s8 interesting_8[]  = { INTERESTING_8 };
s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* 额外的全局变量 */
u8  first_run = 1;                /* 首次运行标志 */
u32 ret_val = 0;                  /* 返回值 */

/* 效果映射数组 */
u8 eff_map[MAP_SIZE];

/* 初始化函数 */
void init_globals(void) {
  /* 这里可以添加任何需要的初始化代码 */
}

/* 清理函数 */
void cleanup_globals(void) {
  /* 这里可以添加任何需要的清理代码 */
}

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}










/* Configure shared memory and virgin_bits. This is called at startup. */

void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (trace_bits == (void *)-1) PFATAL("shmat() failed");

}

