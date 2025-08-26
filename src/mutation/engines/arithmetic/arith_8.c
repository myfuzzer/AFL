#include "arithmetic_engine.h"

u8 fuzz_arith_8(char** argv, fuzz_context_t* ctx) {
    
    stage_name  = "arith 8/8";
    stage_short = "arith8";
    ctx->stage_cur   = 0;
    stage_max   = 2 * ctx->len * ARITH_MAX;
    stage_val_type = STAGE_VAL_LE;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len; i++) {
        
        u8 orig = ctx->out_buf[i];
        
        // 查询效应图
        if (!ctx->eff_map[EFF_APOS(i)]) {
            stage_max -= 2 * ARITH_MAX;
            continue;
        }
        
        ctx->stage_cur_byte = i;
        
        for (s32 j = 1; j <= ARITH_MAX; j++) {
            
            u8 r = orig ^ (orig + j);
            
            // 只有在结果不是位翻转的产物时才执行算术运算
            if (!could_be_bitflip(r)) {
                
                ctx->stage_cur_val = j;
                ctx->out_buf[i] = orig + j;
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            r = orig ^ (orig - j);
            
            if (!could_be_bitflip(r)) {
                
                ctx->stage_cur_val = -j;
                ctx->out_buf[i] = orig - j;
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            ctx->out_buf[i] = orig;
        }
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_ARITH8]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_ARITH8] += stage_max;
    
    return 0;
}