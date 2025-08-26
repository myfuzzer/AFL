#ifndef FUZZ_CONTEXT_H
#define FUZZ_CONTEXT_H

#include "../mutations.h"

/* 效应图相关宏定义 */
#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

typedef struct fuzz_context {
    u8 *in_buf;           // 输入缓冲区
    u8 *out_buf;          // 输出缓冲区  
    u8 *orig_in;          // 原始输入
    u8 *eff_map;          // 效应图
    
    s32 len;              // 当前长度
    s32 temp_len;         // 临时长度
    u32 eff_cnt;          // 效应计数
    
    u64 orig_hit_cnt;     // 原始命中数
    u64 new_hit_cnt;      // 新命中数
    u32 perf_score;       // 性能分数
    u32 orig_perf;        // 原始性能分数
    
    u32 stage_cur;        // 当前阶段计数
    u32 stage_max;        // 阶段最大计数
    s32 stage_cur_byte;   // 当前字节位置
    s32 stage_cur_val;    // 当前值
    
    // 字典收集相关
    u8 a_collect[MAX_AUTO_EXTRA];
    u32 a_len;
    u32 prev_cksum;
    
    // Havoc 相关
    u64 havoc_queued;
    u32 splice_cycle;
    
} fuzz_context_t;

// 上下文管理函数
u8 init_fuzz_context(fuzz_context_t* ctx, char** argv);
void cleanup_fuzz_context(fuzz_context_t* ctx);
u8 setup_effector_map(fuzz_context_t* ctx);

#endif