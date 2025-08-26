#include "interesting_engine.h"

u8 fuzz_interest_8(char** argv, fuzz_context_t* ctx) {
    stage_name  = "interest 8/8";
    stage_short = "int8";
    ctx->stage_cur   = 0;
    stage_max   = ctx->len * sizeof(interesting_8);
    stage_val_type = STAGE_VAL_LE;
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len; i++) {
        u8 orig = ctx->out_buf[i];
        
        if (!ctx->eff_map[EFF_APOS(i)]) {
            stage_max -= sizeof(interesting_8);
            continue;
        }
        
        ctx->stage_cur_byte = i;
        
        for (s32 j = 0; j < sizeof(interesting_8); j++) {
            if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
                could_be_arith(orig, (u8)interesting_8[j], 1)) {
                stage_max--;
                continue;
            }
            
            ctx->stage_cur_val = interesting_8[j];
            ctx->out_buf[i] = interesting_8[j];
            
            if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
            
            ctx->out_buf[i] = orig;
            ctx->stage_cur++;
        }
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_INTEREST8]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_INTEREST8] += stage_max;
    
    return 0;
}

u8 fuzz_interest_16(char** argv, fuzz_context_t* ctx) {
    if (no_arith || ctx->len < 2) return 0;
    
    stage_name  = "interest 16/8";
    stage_short = "int16";
    ctx->stage_cur   = 0;
    stage_max   = 2 * (ctx->len - 1) * (sizeof(interesting_16) >> 1);
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len - 1; i++) {
        u16 orig = *(u16*)(ctx->out_buf + i);
        
        if (!ctx->eff_map[EFF_APOS(i)] && !ctx->eff_map[EFF_APOS(i + 1)]) {
            stage_max -= sizeof(interesting_16);
            continue;
        }
        
        ctx->stage_cur_byte = i;
        
        for (s32 j = 0; j < sizeof(interesting_16) / 2; j++) {
            ctx->stage_cur_val = interesting_16[j];
            
            if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
                !could_be_arith(orig, (u16)interesting_16[j], 2) &&
                !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {
                
                stage_val_type = STAGE_VAL_LE;
                *(u16*)(ctx->out_buf + i) = interesting_16[j];
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
                !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
                !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
                !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {
                
                stage_val_type = STAGE_VAL_BE;
                *(u16*)(ctx->out_buf + i) = SWAP16(interesting_16[j]);
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
        }
        
        *(u16*)(ctx->out_buf + i) = orig;
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_INTEREST16]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_INTEREST16] += stage_max;
    
    return 0;
}

u8 fuzz_interest_32(char** argv, fuzz_context_t* ctx) {
    if (ctx->len < 4) return 0;
    
    stage_name  = "interest 32/8";
    stage_short = "int32";
    ctx->stage_cur   = 0;
    stage_max   = 2 * (ctx->len - 3) * (sizeof(interesting_32) >> 2);
    
    ctx->orig_hit_cnt = ctx->new_hit_cnt;
    
    for (s32 i = 0; i < ctx->len - 3; i++) {
        u32 orig = *(u32*)(ctx->out_buf + i);
        
        if (!ctx->eff_map[EFF_APOS(i)] && !ctx->eff_map[EFF_APOS(i + 1)] &&
            !ctx->eff_map[EFF_APOS(i + 2)] && !ctx->eff_map[EFF_APOS(i + 3)]) {
            stage_max -= sizeof(interesting_32) >> 1;
            continue;
        }
        
        ctx->stage_cur_byte = i;
        
        for (s32 j = 0; j < sizeof(interesting_32) / 4; j++) {
            ctx->stage_cur_val = interesting_32[j];
            
            if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
                !could_be_arith(orig, interesting_32[j], 4) &&
                !could_be_interest(orig, interesting_32[j], 4, 0)) {
                
                stage_val_type = STAGE_VAL_LE;
                *(u32*)(ctx->out_buf + i) = interesting_32[j];
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
            
            if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
                !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
                !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
                !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {
                
                stage_val_type = STAGE_VAL_BE;
                *(u32*)(ctx->out_buf + i) = SWAP32(interesting_32[j]);
                
                if (common_fuzz_stuff(argv, ctx->out_buf, ctx->len)) return 1;
                ctx->stage_cur++;
                
            } else stage_max--;
        }
        
        *(u32*)(ctx->out_buf + i) = orig;
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    stage_finds[STAGE_INTEREST32]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
    stage_cycles[STAGE_INTEREST32] += stage_max;
    
    return 0;
}

u8 fuzz_interesting_stages(char** argv, fuzz_context_t* ctx) {
    if (fuzz_interest_8(argv, ctx)) return 1;
    if (fuzz_interest_16(argv, ctx)) return 1;
    if (fuzz_interest_32(argv, ctx)) return 1;
    return 0;
}