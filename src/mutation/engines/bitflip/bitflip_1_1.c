#include "bitflip_engine.h"

u8 fuzz_bitflip_1_1(char** argv, fuzz_context_t* ctx) {
    
    stage_short = "flip1";
    stage_max   = ctx->len << 3;
    stage_name  = "bitflip 1/1";
    stage_val_type = STAGE_VAL_NONE;
    
    ctx->orig_hit_cnt = queued_paths + unique_crashes;
    ctx->prev_cksum = queue_cur->exec_cksum;
    
    for (ctx->stage_cur = 0; ctx->stage_cur < stage_max; ctx->stage_cur++) {
        
        ctx->stage_cur_byte = ctx->stage_cur >> 3;
        
        FLIP_BIT(ctx->out_buf, ctx->stage_cur);
        
        if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
        
        FLIP_BIT(ctx->out_buf, ctx->stage_cur);
        
        // 字典收集逻辑 - 在每个字节的最低位翻转时进行
        if (!dumb_mode && (ctx->stage_cur & 7) == 7) {
            
            u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
            
            if (ctx->stage_cur == stage_max - 1 && cksum == ctx->prev_cksum) {
                
                // 文件末尾且校验和相同，收集最后一个字符
                if (ctx->a_len < MAX_AUTO_EXTRA) 
                    ctx->a_collect[ctx->a_len] = ctx->out_buf[ctx->stage_cur >> 3];
                ctx->a_len++;
                
                if (ctx->a_len >= MIN_AUTO_EXTRA && ctx->a_len <= MAX_AUTO_EXTRA)
                    maybe_add_auto(ctx->a_collect, ctx->a_len);
                    
            } else if (cksum != ctx->prev_cksum) {
                
                // 校验和改变，输出之前收集的字符串
                if (ctx->a_len >= MIN_AUTO_EXTRA && ctx->a_len <= MAX_AUTO_EXTRA)
                    maybe_add_auto(ctx->a_collect, ctx->a_len);
                
                ctx->a_len = 0;
                ctx->prev_cksum = cksum;
            }
            
            // 继续收集字符串，但仅在位翻转确实有效果时
            if (cksum != queue_cur->exec_cksum) {
                if (ctx->a_len < MAX_AUTO_EXTRA) 
                    ctx->a_collect[ctx->a_len] = ctx->out_buf[ctx->stage_cur >> 3];        
                ctx->a_len++;
            }
        }
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FLIP1]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_FLIP1] += stage_max;
    
    return 0;
}