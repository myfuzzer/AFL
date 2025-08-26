#include "mutations.h"

/* 修剪所有新的测试用例，以在进行确定性检查时节省周期。 
   修剪器使用介于文件大小的 1/16 和 1/1024 之间的
   2 的幂次方增量，以保持阶段简短而有效。*/

u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf) {

  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  /* 尽管在检测到可变行为时修剪器将不那么有用，
     但它在某种程度上仍然有效，所以我们不检查
     这个。*/

  if (q->len < 5) return 0;

  stage_name = tmp;
  bytes_trim_in += q->len;

  /* 选择初始块长度，从大步长开始。*/

  len_p2 = next_p2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

  /* 继续，直到步数变得太高或步长
     变得太小。*/

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

    stage_cur = 0;
    stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 cksum;

      write_with_gap(in_buf, q->len, remove_pos, trim_avail);

      fault = run_target(argv, exec_tmout);
      trim_execs++;

      if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

      /* 注意，我们在这里不跟踪崩溃或挂起；也许是 TODO？*/

      cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      /* 如果删除对跟踪没有影响，则使其永久化。这
         对于可变路径输入来说并不完美，但我们只是在尽力而为，
         所以如果我们偶尔得到假阴性，也不是什么大问题。*/

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2  = next_p2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail, 
                move_tail);

        /* 让我们保存一个干净的跟踪，一旦我们完成了修剪工作，
           update_bitmap_score 将需要它。*/

        if (!needs_write) {

          needs_write = 1;
          memcpy(clean_trace, trace_bits, MAP_SIZE);

        }

      } else remove_pos += remove_len;

      /* 因为这可能很慢，所以不时更新屏幕。*/

      if (!(trim_exec++ % stats_update_freq)) show_stats();
      stage_cur++;

    }

    remove_len >>= 1;

  }

  /* 如果我们对 in_buf 进行了更改，我们还需要更新
     测试用例的磁盘版本。*/

  if (needs_write) {

    s32 fd;

    unlink(q->fname); /* 忽略错误 */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);

  }

abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}


/* maybe_add_auto() 的辅助函数 */

u8 memcmp_nocase(u8* m1, u8* m2, u32 len) {

  while (len--) if (tolower(*(m1++)) ^ tolower(*(m2++))) return 1;
  return 0;

}

