
#include "queue.h"
#include "../utils/timing.h"
#include "../analysis/bitmap.h"
#include "../io/file_ops.h"
#include "../mutation/mutations.h"
#include "../core/executor.h"

extern struct queue_entry *queue, *queue_cur, *queue_top, *q_prev100;
extern u32 queued_paths, pending_not_fuzzed, cur_depth, max_depth;
extern u64 cycles_wo_finds;
extern u64 last_path_time;
extern u8 *out_dir;


/* 将新测试用例附加到队列中。*/

void add_to_queue(u8* fname, u32 len, u8 passed_det) {

  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  q->fname        = fname;
  q->len          = len;
  q->depth        = cur_depth + 1;
  q->passed_det   = passed_det;

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {

    queue_top->next = q;
    queue_top = q;

  } else q_prev100 = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  /* 为每第 100 个元素（索引 0、100 等）设置 next_100 指针，以加快迭代速度。*/
  if ((queued_paths - 1) % 100 == 0 && queued_paths > 1) {

    q_prev100->next_100 = q;
    q_prev100 = q;

  }

  last_path_time = get_cur_time();

}



/* 销毁整个队列。*/

void destroy_queue(void) {

  struct queue_entry *q = queue, *n;

  while (q) {

    n = q->next;
    ck_free(q->fname);
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;

  }

}


/* 将特定队列条目的确定性检查标记为已完成。我们使用
   .state 文件来避免在恢复中止的扫描时重复确定性模糊测试。*/

void mark_as_det_done(struct queue_entry* q) {

  u8* fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;

}


/* 标记为可变。如果可能，创建符号链接以便于检查
   文件。*/

void mark_as_variable(struct queue_entry* q) {

  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn)) {

    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;

}





/* 标记/取消标记为冗余（仅边）。这不用于恢复状态，
   但可能对后处理数据集有用。*/

void mark_as_redundant(struct queue_entry* q, u8 state) {

  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state) {

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {

    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);

  }

  ck_free(fn);

}


extern struct queue_entry* top_rated[MAP_SIZE];
extern u32 queued_favored, pending_favored, queued_variable;
extern u8 score_changed, dumb_mode;





/* 上面讨论的机制的第二部分是一个例程，它
   遍历 top_rated[] 条目，然后依次获取
   先前未见过的字节 (temp_v) 的获胜者，并将它们标记为受青睐的，至少
   在下一次运行之前是这样。在所有模糊测试步骤中，受青睐的条目会获得更多的播出时间。*/

void cull_queue(void) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* 让我们看看位图中是否有任何东西没有被 temp_v 捕获。
     如果是，并且它有一个 top_rated[] 竞争者，让我们使用它。*/

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* 从 temp_v 中删除属于当前条目的所有位。*/

      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;

    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }

}






extern u64 total_bitmap_size, total_bitmap_entries;
extern u8* trace_bits;



/* 当我们遇到一条新路径时，我们会调用它来查看该路径是否出现
   比任何现有路径都更“有利”。“有利”的目的是
   拥有一组最小的路径，这些路径可以触发迄今为止在位图中看到的所有位，
   并专注于对它们进行模糊测试，而牺牲其余的路径。

   该过程的第一步是为位图中的每个字节维护一个 top_rated[] 条目列表。
   如果没有先前的竞争者，或者竞争者的速度 x 大小因子更有利，
   我们就会赢得该位置。*/

void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* 对于 trace_bits[] 中设置的每个字节，查看是否有先前的获胜者，
     以及它与我们的比较情况。*/

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {

         /* 执行速度更快或体积更小的测试用例更受青睐。*/

         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

         /* 看来我们要赢了。减少前一个获胜者的引用计数，
            必要时丢弃其 trace_bits[]。*/

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }

       /* 将我们自己插入为新的获胜者。*/

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }

       score_changed = 1;

     }

}

/* 检查在常规模糊测试期间 execve() 的结果是否有趣，
   如果是，则保存或排队输入测试用例以供进一步分析。如果
   条目已保存，则返回 1，否则返回 0。*/

u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {

  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  if (fault == crash_mode) {

    /* 仅在映射中有新位时才保留，添加到队列中以备
       将来的模糊测试等。*/

    if (!(hnb = has_new_bits(virgin_bits))) {
      if (crash_mode) total_crashes++;
      return 0;
    }    

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue(fn, len, 0);

    if (hnb == 2) {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }

    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    /* 尝试内联校准；这在成功时也会调用 update_bitmap_score()。*/

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_TMOUT:

      /* 超时不是很有趣，但我们仍然有义务保留
         少量样本。我们使用特定于挂起的位图中新位的存在
         作为唯一性的信号。在“哑”模式下，我们
         只保留所有内容。*/

      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_tmout)) return keeping;

      }

      unique_tmouts++;

      /* 在保存之前，我们通过使用更宽松的超时重新运行目标来确保
         它是一个真正的挂起（除非默认超时
         已经很宽松了）。*/

      if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_target(argv, hang_tmout);

        /* 一个用户报告遇到的极端情况：增加
           超时实际上发现了一个崩溃。确保我们不会丢弃它，如果
           是这样的话。*/

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

keep_as_crash:

      /* 这以与超时大致相似的方式处理，
         除了略有不同的限制和无需重新运行测试
         用例。*/

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      unique_crashes++;

      last_crash_time = get_cur_time();
      last_crash_execs = total_execs;

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* 如果我们在这里，我们显然也想保存崩溃或挂起的
     测试用例。*/

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}


