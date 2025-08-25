/*
   american fuzzy lop - 队列管理模块实现
   ====================================

   实现测试用例队列的管理功能
*/

#include "queue.h"
#include "../utils/timing.h"
#include "../analysis/bitmap.h"

extern struct queue_entry *queue, *queue_cur, *queue_top, *q_prev100;
extern u32 queued_paths, pending_not_fuzzed, cur_depth, max_depth;
extern u64 cycles_wo_finds;
extern u64 last_path_time;
extern u8 *out_dir;

/* 将新测试用例添加到队列 */
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

  /* 为每100个元素（索引0、100等）设置next_100指针以允许更快的迭代 */
  if ((queued_paths - 1) % 100 == 0 && queued_paths > 1) {
    q_prev100->next_100 = q;
    q_prev100 = q;
  }

  last_path_time = get_cur_time();
}

/* 销毁整个队列 */
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

/* 将确定性检查标记为对特定队列条目完成。我们使用.state文件
   来避免在恢复中止的扫描时重复确定性模糊测试 */
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

/* 标记为可变。如果可能，创建符号链接以便更容易检查文件 */
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

/* 标记/取消标记为冗余（仅边缘）。这不用于恢复状态，
   但对于后处理数据集可能有用 */
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

/* 上述机制讨论的第二部分是一个例程，它遍历top_rated[]条目，
   然后依次抓取先前未见字节的获胜者（temp_v）并将其标记为偏爱的，
   至少在下一次运行之前。偏爱的条目在所有模糊测试步骤中获得更多的播放时间 */
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

  /* 让我们看看位图中是否有任何内容没有在temp_v中捕获。
     如果是，并且它有top_rated[]竞争者，让我们使用它 */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* 从temp_v中删除属于当前条目的所有位 */

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

/* 当我们遇到新路径时，我们调用这个来查看路径是否比任何现有路径看起来更"有利"。
   "收藏夹"的目的是拥有一组触发迄今为止在位图中看到的所有位的最小路径集，
   并专注于模糊测试它们而不是其余的 */
void update_bitmap_score(struct queue_entry* q) {
  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* 对于trace_bits[]中设置的每个字节，看看是否有先前的获胜者，
     以及它与我们的比较如何 */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {

         /* 更快执行或更小的测试用例是首选的 */

         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

         /* 看起来我们要赢了。减少先前获胜者的引用计数，
            如果必要，丢弃其trace_bits[] */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }

       /* 将我们自己作为新的获胜者插入 */

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }

       score_changed = 1;

     }
}