#include "dictionary_engine.h"

u8 fuzz_user_extras_over(char** argv, fuzz_context_t* ctx) {
    if (!extras_cnt) return 0;
    
    stage_name  = "user extras (over)";
    stage_short = "ext_UO";
    ctx->stage_cur   = 0;
    stage_max   = extras_cnt * ctx->len;
    stage_val_type = STAGE_VAL_NONE;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len; i++) {
        u32 last_len = 0;
        ctx->stage_cur_byte = i;
        
        for (s32 j = 0; j < extras_cnt; j++) {
            if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
                extras[j].len > ctx->len - i ||
                !memcmp(extras[j].data, ctx->out_buf + i, extras[j].len) ||
                !memchr(ctx->eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {
                stage_max--;
                continue;
            }
            
            last_len = extras[j].len;
            memcpy(ctx->out_buf + i, extras[j].data, last_len);
            
            if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
            ctx->stage_cur++;
        }
        
        memcpy(ctx->out_buf + i, ctx->in_buf + i, last_len);
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_EXTRAS_UO]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UO] += stage_max;
    
    return 0;
}

u8 fuzz_user_extras_insert(char** argv, fuzz_context_t* ctx) {
    if (!extras_cnt) return 0;
    
    stage_name  = "user extras (insert)";
    stage_short = "ext_UI";
    ctx->stage_cur   = 0;
    stage_max   = extras_cnt * (ctx->len + 1);
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    u8* ex_tmp = ck_alloc(ctx->len + MAX_DICT_FILE);
    
    for (s32 i = 0; i <= ctx->len; i++) {
        ctx->stage_cur_byte = i;
        
        for (s32 j = 0; j < extras_cnt; j++) {
            if (ctx->len + extras[j].len > MAX_FILE) {
                stage_max--; 
                continue;
            }
            
            memcpy(ex_tmp + i, extras[j].data, extras[j].len);
            memcpy(ex_tmp + i + extras[j].len, ctx->out_buf + i, ctx->len - i);
            
            if (common_fuzz_stuff(argv, ex_tmp, ctx->len + extras[j].len)) {
                ck_free(ex_tmp);
                return 1;
            }
            
            ctx->stage_cur++;
        }
        
        ex_tmp[i] = ctx->out_buf[i];
    }
    
    ck_free(ex_tmp);
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_EXTRAS_UI]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_UI] += stage_max;
    
    return 0;
}

u8 fuzz_auto_extras_over(char** argv, fuzz_context_t* ctx) {
    if (!a_extras_cnt) return 0;
    
    stage_name  = "auto extras (over)";
    stage_short = "ext_AO";
    ctx->stage_cur   = 0;
    stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * ctx->len;
    stage_val_type = STAGE_VAL_NONE;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len; i++) {
        u32 last_len = 0;
        ctx->stage_cur_byte = i;
        
        for (s32 j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {
            if (a_extras[j].len > ctx->len - i ||
                !memcmp(a_extras[j].data, ctx->out_buf + i, a_extras[j].len) ||
                !memchr(ctx->eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {
                stage_max--;
                continue;
            }
            
            last_len = a_extras[j].len;
            memcpy(ctx->out_buf + i, a_extras[j].data, last_len);
            
            if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
            ctx->stage_cur++;
        }
        
        memcpy(ctx->out_buf + i, ctx->in_buf + i, last_len);
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_EXTRAS_AO]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_EXTRAS_AO] += stage_max;
    
    return 0;
}

u8 fuzz_dictionary_stages(char** argv, fuzz_context_t* ctx) {
    if (fuzz_user_extras_over(argv, ctx)) return 1;
    if (fuzz_user_extras_insert(argv, ctx)) return 1;
    if (fuzz_auto_extras_over(argv, ctx)) return 1;
    return 0;
}