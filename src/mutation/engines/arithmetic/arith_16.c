#include "arithmetic_engine.h"

u8 fuzz_arith_16(char** argv, fuzz_context_t* ctx) {
    
    if (ctx->len < 2) return 0;
    
    stage_name  = "arith 16/8";
    stage_short = "arith16";
    ctx->stage_cur   = 0;
    stage_max   = 4 * (ctx->len - 1) * ARITH_MAX;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len - 1; i++) {
        
        u16 orig = *(u16*)(ctx->out_buf + i);
        
        // 查询效应图
        if (!ctx->eff_map[EFF_APOS(i)] && !ctx->eff_map[EFF_APOS(i + 1)]) {
            stage_max -= 4 * ARITH_MAX;
            continue;
        }
        
        ctx->stage_cur_byte = i;
        
        for (s32 j = 1; j <= ARITH_MAX; j++) {
            
            u16 r1 = orig ^ (orig + j),
                r2 = orig ^ (orig - j),
                r3 = orig ^ SWAP16(SWAP16(orig) + j),
                r4 = orig ^ SWAP16(SWAP16(orig) - j);
            
            // 小端序加法和减法
            stage_val_type = STAGE_VAL_LE; 
            
            if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {
                
                ctx->stage_cur_val = j;
                *(u16*)(ctx->out_buf + i) = orig + j;
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            if ((orig & 0xff) < j && !could_be_bitflip(r2)) {
                
                ctx->stage_cur_val = -j;
                *(u16*)(ctx->out_buf + i) = orig - j;
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            // 大端序处理
            stage_val_type = STAGE_VAL_BE;
            
            if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {
                
                ctx->stage_cur_val = j;
                *(u16*)(ctx->out_buf + i) = SWAP16(SWAP16(orig) + j);
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            if ((orig >> 8) < j && !could_be_bitflip(r4)) {
                
                ctx->stage_cur_val = -j;
                *(u16*)(ctx->out_buf + i) = SWAP16(SWAP16(orig) - j);
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            *(u16*)(ctx->out_buf + i) = orig;
        }
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_ARITH16]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_ARITH16] += stage_max;
    
    return 0;
}