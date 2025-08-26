#include "bitflip_engine.h"

u8 fuzz_bitflip_8_8(char** argv, fuzz_context_t* ctx) {
    
    stage_name  = "bitflip 8/8";
    stage_short = "flip8";
    stage_max   = ctx->len;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (ctx->stage_cur = 0; ctx->stage_cur < stage_max; ctx->stage_cur++) {
        
        ctx->stage_cur_byte = ctx->stage_cur;
        
        ctx->out_buf[ctx->stage_cur] ^= 0xFF;
        
        if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
        
        // 使用此阶段识别对执行路径没有影响的字节
        if (!ctx->eff_map[EFF_APOS(ctx->stage_cur)]) {
            
            u32 cksum;
            
            // 如果在哑模式或文件很短，直接标记所有字节
            if (!dumb_mode && ctx->len >= EFF_MIN_LEN)
                cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
            else
                cksum = ~queue_cur->exec_cksum;
            
            if (cksum != queue_cur->exec_cksum) {
                ctx->eff_map[EFF_APOS(ctx->stage_cur)] = 1;
                ctx->eff_cnt++;
            }
        }
        
        ctx->out_buf[ctx->stage_cur] ^= 0xFF;
    }
    
    // 如果效应图密度太高，就标记整个文件都值得模糊测试
    if (ctx->eff_cnt != EFF_ALEN(ctx->len) &&
        ctx->eff_cnt * 100 / EFF_ALEN(ctx->len) > EFF_MAX_PERC) {
        
        memset(ctx->eff_map, 1, EFF_ALEN(ctx->len));
        blocks_eff_select += EFF_ALEN(ctx->len);
        
    } else {
        blocks_eff_select += ctx->eff_cnt;
    }
    
    blocks_eff_total += EFF_ALEN(ctx->len);
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FLIP8]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_FLIP8] += stage_max;
    
    return 0;
}