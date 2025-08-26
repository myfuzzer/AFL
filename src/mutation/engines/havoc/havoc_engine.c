#include "havoc_engine.h"

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

u8 fuzz_havoc_stage(char** argv, fuzz_context_t* ctx, u32 splice_cycle, u8 doing_det) {
    
    // doing_det 现在从主引擎传入，表示是否刚完成确定性测试
    s32 i;
    
    ctx->stage_cur_byte = -1;
    
    // Havoc阶段或Splice阶段的设置
    if (!splice_cycle) {
        stage_name  = "havoc";
        stage_short = "havoc";
        stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                      ctx->perf_score / havoc_div / 100;
    } else {
        static u8 tmp[32];
        ctx->perf_score = ctx->orig_perf;
        sprintf(tmp, "splice %u", splice_cycle);
        stage_name  = tmp;
        stage_short = "splice";
        stage_max   = SPLICE_HAVOC * ctx->perf_score / havoc_div / 100;
    }
    
    if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
    
    ctx->temp_len = ctx->len;
    ctx->orig_hit_cnt = queued_paths + unique_crashes;
    ctx->havoc_queued = queued_paths;
    
    // 进行几千次运行，每次都对输入文件进行随机的叠加调整
    for (ctx->stage_cur = 0; ctx->stage_cur < stage_max; ctx->stage_cur++) {
        
        u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));
        ctx->stage_cur_val = use_stacking;
        
        for (i = 0; i < use_stacking; i++) {
            
            switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {
                
                case 0:
                    // 随机翻转一个比特位
                    FLIP_BIT(ctx->out_buf, UR(ctx->temp_len << 3));
                    break;
                    
                case 1:
                    // 设置字节为有趣的值
                    ctx->out_buf[UR(ctx->temp_len)] = interesting_8[UR(sizeof(interesting_8))];
                    break;
                    
                case 2:
                    // 设置字（word）为有趣的值，随机选择端序
                    if (ctx->temp_len < 2) break;
                    
                    if (UR(2)) {
                        *(u16*)(ctx->out_buf + UR(ctx->temp_len - 1)) =
                          interesting_16[UR(sizeof(interesting_16) >> 1)];
                    } else {
                        *(u16*)(ctx->out_buf + UR(ctx->temp_len - 1)) = SWAP16(
                          interesting_16[UR(sizeof(interesting_16) >> 1)]);
                    }
                    break;
                    
                case 3:
                    // 设置双字（dword）为有趣的值，随机选择端序
                    if (ctx->temp_len < 4) break;
                    
                    if (UR(2)) {
                        *(u32*)(ctx->out_buf + UR(ctx->temp_len - 3)) =
                          interesting_32[UR(sizeof(interesting_32) >> 2)];
                    } else {
                        *(u32*)(ctx->out_buf + UR(ctx->temp_len - 3)) = SWAP32(
                          interesting_32[UR(sizeof(interesting_32) >> 2)]);
                    }
                    break;
                    
                case 4:
                    // 随机从字节中减去值
                    ctx->out_buf[UR(ctx->temp_len)] -= 1 + UR(ARITH_MAX);
                    break;
                    
                case 5:
                    // 随机给字节加上值
                    ctx->out_buf[UR(ctx->temp_len)] += 1 + UR(ARITH_MAX);
                    break;
                    
                case 6:
                    // 随机从字中减去值，随机端序
                    if (ctx->temp_len < 2) break;
                    
                    if (UR(2)) {
                        u32 pos = UR(ctx->temp_len - 1);
                        *(u16*)(ctx->out_buf + pos) -= 1 + UR(ARITH_MAX);
                    } else {
                        u32 pos = UR(ctx->temp_len - 1);
                        u16 num = 1 + UR(ARITH_MAX);
                        *(u16*)(ctx->out_buf + pos) =
                          SWAP16(SWAP16(*(u16*)(ctx->out_buf + pos)) - num);
                    }
                    break;
                    
                case 7:
                    // 随机给字加上值，随机端序
                    if (ctx->temp_len < 2) break;
                    
                    if (UR(2)) {
                        u32 pos = UR(ctx->temp_len - 1);
                        *(u16*)(ctx->out_buf + pos) += 1 + UR(ARITH_MAX);
                    } else {
                        u32 pos = UR(ctx->temp_len - 1);
                        u16 num = 1 + UR(ARITH_MAX);
                        *(u16*)(ctx->out_buf + pos) =
                          SWAP16(SWAP16(*(u16*)(ctx->out_buf + pos)) + num);
                    }
                    break;
                    
                case 8:
                    // 随机从双字中减去值，随机端序
                    if (ctx->temp_len < 4) break;
                    
                    if (UR(2)) {
                        u32 pos = UR(ctx->temp_len - 3);
                        *(u32*)(ctx->out_buf + pos) -= 1 + UR(ARITH_MAX);
                    } else {
                        u32 pos = UR(ctx->temp_len - 3);
                        u32 num = 1 + UR(ARITH_MAX);
                        *(u32*)(ctx->out_buf + pos) =
                          SWAP32(SWAP32(*(u32*)(ctx->out_buf + pos)) - num);
                    }
                    break;
                    
                case 9:
                    // 随机给双字加上值，随机端序
                    if (ctx->temp_len < 4) break;
                    
                    if (UR(2)) {
                        u32 pos = UR(ctx->temp_len - 3);
                        *(u32*)(ctx->out_buf + pos) += 1 + UR(ARITH_MAX);
                    } else {
                        u32 pos = UR(ctx->temp_len - 3);
                        u32 num = 1 + UR(ARITH_MAX);
                        *(u32*)(ctx->out_buf + pos) =
                          SWAP32(SWAP32(*(u32*)(ctx->out_buf + pos)) + num);
                    }
                    break;
                    
                case 10:
                    // 随机设置一个字节为随机值
                    // 使用 XOR 1-255 来避免 no-op
                    ctx->out_buf[UR(ctx->temp_len)] ^= 1 + UR(255);
                    break;
                    
                case 11 ... 12: {
                    // 删除字节。比插入更频繁一些，希望文件大小合理
                    u32 del_from, del_len;
                    
                    if (ctx->temp_len < 2) break;
                    
                    // 不要删除太多
                    del_len = choose_block_len(ctx->temp_len - 1);
                    del_from = UR(ctx->temp_len - del_len + 1);
                    
                    memmove(ctx->out_buf + del_from, ctx->out_buf + del_from + del_len,
                            ctx->temp_len - del_from - del_len);
                    
                    ctx->temp_len -= del_len;
                    break;
                }
                    
                case 13:
                    if (ctx->temp_len + HAVOC_BLK_XL < MAX_FILE) {
                        // 克隆字节（75%）或插入常量字节块（25%）
                        u8  actually_clone = UR(4);
                        u32 clone_from, clone_to, clone_len;
                        u8* new_buf;
                        
                        if (actually_clone) {
                            clone_len  = choose_block_len(ctx->temp_len);
                            clone_from = UR(ctx->temp_len - clone_len + 1);
                        } else {
                            clone_len = choose_block_len(HAVOC_BLK_XL);
                            clone_from = 0;
                        }
                        
                        clone_to   = UR(ctx->temp_len);
                        new_buf = ck_alloc_nozero(ctx->temp_len + clone_len);
                        
                        // 头部
                        memcpy(new_buf, ctx->out_buf, clone_to);
                        
                        // 插入部分
                        if (actually_clone)
                            memcpy(new_buf + clone_to, ctx->out_buf + clone_from, clone_len);
                        else
                            memset(new_buf + clone_to,
                                   UR(2) ? UR(256) : ctx->out_buf[UR(ctx->temp_len)], clone_len);
                        
                        // 尾部
                        memcpy(new_buf + clone_to + clone_len, ctx->out_buf + clone_to,
                               ctx->temp_len - clone_to);
                        
                        ck_free(ctx->out_buf);
                        ctx->out_buf = new_buf;
                        ctx->temp_len += clone_len;
                    }
                    break;
                    
                case 14: {
                    // 用随机选择的块（75%）或固定字节（25%）覆盖字节
                    u32 copy_from, copy_to, copy_len;
                    
                    if (ctx->temp_len < 2) break;
                    
                    copy_len  = choose_block_len(ctx->temp_len - 1);
                    copy_from = UR(ctx->temp_len - copy_len + 1);
                    copy_to   = UR(ctx->temp_len - copy_len + 1);
                    
                    if (UR(4)) {
                        if (copy_from != copy_to)
                            memmove(ctx->out_buf + copy_to, ctx->out_buf + copy_from, copy_len);
                    } else {
                        memset(ctx->out_buf + copy_to,
                               UR(2) ? UR(256) : ctx->out_buf[UR(ctx->temp_len)], copy_len);
                    }
                    break;
                }
                    
                // 只有在字典中有额外条目时才能选择值15和16
                case 15: {
                    // 用额外条目覆盖字节
                    if (!extras_cnt || (a_extras_cnt && UR(2))) {
                        // 没有用户指定的额外条目或对我们有利。使用自动检测的
                        u32 use_extra = UR(a_extras_cnt);
                        u32 extra_len = a_extras[use_extra].len;
                        u32 insert_at;
                        
                        if (extra_len > ctx->temp_len) break;
                        
                        insert_at = UR(ctx->temp_len - extra_len + 1);
                        memcpy(ctx->out_buf + insert_at, a_extras[use_extra].data, extra_len);
                        
                    } else {
                        // 没有自动额外条目或对我们有利。使用字典
                        u32 use_extra = UR(extras_cnt);
                        u32 extra_len = extras[use_extra].len;
                        u32 insert_at;
                        
                        if (extra_len > ctx->temp_len) break;
                        
                        insert_at = UR(ctx->temp_len - extra_len + 1);
                        memcpy(ctx->out_buf + insert_at, extras[use_extra].data, extra_len);
                    }
                    break;
                }
                    
                case 16: {
                    // 插入额外条目
                    u32 use_extra, extra_len, insert_at = UR(ctx->temp_len + 1);
                    u8* new_buf;
                    
                    if (!extras_cnt || (a_extras_cnt && UR(2))) {
                        use_extra = UR(a_extras_cnt);
                        extra_len = a_extras[use_extra].len;
                        
                        if (ctx->temp_len + extra_len >= MAX_FILE) break;
                        
                        new_buf = ck_alloc_nozero(ctx->temp_len + extra_len);
                        
                        // 头部
                        memcpy(new_buf, ctx->out_buf, insert_at);
                        
                        // 插入部分
                        memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);
                        
                    } else {
                        use_extra = UR(extras_cnt);
                        extra_len = extras[use_extra].len;
                        
                        if (ctx->temp_len + extra_len >= MAX_FILE) break;
                        
                        new_buf = ck_alloc_nozero(ctx->temp_len + extra_len);
                        
                        // 头部
                        memcpy(new_buf, ctx->out_buf, insert_at);
                        
                        // 插入部分
                        memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);
                    }
                    
                    // 尾部
                    memcpy(new_buf + insert_at + extra_len, ctx->out_buf + insert_at,
                           ctx->temp_len - insert_at);
                    
                    ck_free(ctx->out_buf);
                    ctx->out_buf   = new_buf;
                    ctx->temp_len += extra_len;
                    
                    break;
                }
            }
        }
        
        if (common_fuzz_stuff(argv, ctx->out_buf, ctx->temp_len))
            return 1;
        
        // out_buf可能被修改了一点，所以恢复到原始大小和形状
        if (ctx->temp_len < ctx->len) ctx->out_buf = ck_realloc(ctx->out_buf, ctx->len);
        ctx->temp_len = ctx->len;
        memcpy(ctx->out_buf, ctx->in_buf, ctx->len);
        
        // 如果发现新内容，延长运行时间，如果允许的话
        if (queued_paths != ctx->havoc_queued) {
            if (ctx->perf_score <= HAVOC_MAX_MULT * 100) {
                stage_max  *= 2;
                ctx->perf_score *= 2;
            }
            ctx->havoc_queued = queued_paths;
        }
    }
    
    ctx->new_hit_cnt = queued_paths + unique_crashes;
    
    if (!splice_cycle) {
        stage_finds[STAGE_HAVOC]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
        stage_cycles[STAGE_HAVOC] += stage_max;
    } else {
        stage_finds[STAGE_SPLICE]  += ctx->new_hit_cnt - ctx->orig_hit_cnt;
        stage_cycles[STAGE_SPLICE] += stage_max;
    }
    
    return 0;
}

#undef FLIP_BIT