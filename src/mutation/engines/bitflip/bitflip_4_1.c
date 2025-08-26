#include "bitflip_engine.h"

u8 fuzz_bitflip_4_1(char** argv, fuzz_context_t* ctx) {
    
    stage_name  = "bitflip 4/1";
    stage_short = "flip4";
    stage_max   = (ctx->len << 3) - 3;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (ctx->stage_cur = 0; ctx->stage_cur < stage_max; ctx->stage_cur++) {
        
        ctx->stage_cur_byte = ctx->stage_cur >> 3;
        
        FLIP_BIT(ctx->out_buf, ctx->stage_cur);
        FLIP_BIT(ctx->out_buf, ctx->stage_cur + 1);
        FLIP_BIT(ctx->out_buf, ctx->stage_cur + 2);
        FLIP_BIT(ctx->out_buf, ctx->stage_cur + 3);
        
        if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
        
        FLIP_BIT(ctx->out_buf, ctx->stage_cur);
        FLIP_BIT(ctx->out_buf, ctx->stage_cur + 1);
        FLIP_BIT(ctx->out_buf, ctx->stage_cur + 2);
        FLIP_BIT(ctx->out_buf, ctx->stage_cur + 3);
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_FLIP4]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_FLIP4] += stage_max;
    
    return 0;
}