
#ifndef AFL_QUEUE_H
#define AFL_QUEUE_H

#include "globals.h"

/* 队列管理函数 */
void add_to_queue(u8* fname, u32 len, u8 passed_det);
void destroy_queue(void);
void mark_as_det_done(struct queue_entry* q);
void mark_as_variable(struct queue_entry* q);
void mark_as_redundant(struct queue_entry* q, u8 state);
void cull_queue(void);
void update_bitmap_score(struct queue_entry* q);

#endif /* AFL_QUEUE_H */