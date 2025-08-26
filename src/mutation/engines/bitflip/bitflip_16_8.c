#include "bitflip_engine.h"

u8 fuzz_bitflip_16_8(char** argv, fuzz_context_t* ctx) {
    
    if (ctx->len < 2) return 0;
    
    stage_name  = "bitflip 16/8";
    stage_short = "flip16";
    ctx->stage_cur   = 0;
    stage_max   = ctx->len - 1;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len - 1; i++) {
        
        // 查询效应图
        if (!ctx->eff_map[EFF_APOS(i)] && !ctx->eff_map[EFF_APOS(i + 1)]) {
            stage_max--;
            continue;
        }
        
        ctx->stage_cur_byte = i;
        
        *(u16*)(ctx->out_buf + i) ^= 0xFFFF;
        
        if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
        ctx->stage_cur++;
        
        *(u16*)(ctx->out_buf + i) ^= 0xFFFF;
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FLIP16]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_FLIP16] += stage_max;
    
    return 0;
}