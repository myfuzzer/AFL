#include "bitflip_engine.h"

u8 fuzz_bitflip_32_8(char** argv, fuzz_context_t* ctx) {
    
    if (ctx->len < 4) return 0;
    
    stage_name  = "bitflip 32/8";
    stage_short = "flip32";
    ctx->stage_cur   = 0;
    stage_max   = ctx->len - 3;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len - 3; i++) {
        
        // 查询效应图
        if (!ctx->eff_map[EFF_APOS(i)] && !ctx->eff_map[EFF_APOS(i + 1)] &&
            !ctx->eff_map[EFF_APOS(i + 2)] && !ctx->eff_map[EFF_APOS(i + 3)]) {
            stage_max--;
            continue;
        }
        
        ctx->stage_cur_byte = i;
        
        *(u32*)(ctx->out_buf + i) ^= 0xFFFFFFFF;
        
        if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
        ctx->stage_cur++;
        
        *(u32*)(ctx->out_buf + i) ^= 0xFFFFFFFF;
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FLIP32]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_FLIP32] += stage_max;
    
    return 0;
}