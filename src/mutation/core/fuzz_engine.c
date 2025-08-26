#include "fuzz_engine.h"

u8 init_and_preprocess(char** argv, fuzz_context_t* ctx) {
    
    // 初始化上下文
    if (init_fuzz_context(ctx, argv) != 0) {
        return 1;
    }
    
    // 设置全局变量
    subseq_tmouts = 0;
    cur_depth = queue_cur->depth;
    
    return 0;
}

u8 handle_calibration(char** argv, fuzz_context_t* ctx) {
    
    if (queue_cur->cal_failed) {
        u8 res = FAULT_TMOUT;
        
        if (queue_cur->cal_failed < CAL_CHANCES) {
            queue_cur->exec_cksum = 0;
            res = calibrate_case(argv, queue_cur, ctx->in_buf, queue_cycle - 1, 0);
            
            if (res == FAULT_ERROR)
                FATAL("Unable to execute target application");
        }
        
        if (stop_soon || res != crash_mode) {
            cur_skipped_paths++;
            return 1;
        }
    }
    
    return 0;
}

u8 handle_trimming(char** argv, fuzz_context_t* ctx) {
    
    if (!dumb_mode && !queue_cur->trim_done) {
        u8 res = trim_case(argv, queue_cur, ctx->in_buf);
        
        if (res == FAULT_ERROR)
            FATAL("Unable to execute target application");
        
        if (stop_soon) {
            cur_skipped_paths++;
            return 1;
        }
        
        queue_cur->trim_done = 1;
        
        if (ctx->len != queue_cur->len) {
            ctx->len = queue_cur->len;
        }
    }
    
    // 重新复制数据到输出缓冲区
    memcpy(ctx->out_buf, ctx->in_buf, ctx->len);
    
    return 0;
}

u8 fuzz_one_refactored(char** argv) {
    
    fuzz_context_t ctx = {0};
    u8 ret_val = 1;
    u8 doing_det = 0;
    
#ifdef IGNORE_FINDS
    if (queue_cur->depth > 1) return 1;
#else
    if (pending_favored) {
        if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
            UR(100) < SKIP_TO_NEW_PROB) return 1;
    } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {
        if (queue_cycle > 1 && !queue_cur->was_fuzzed) {
            if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;
        } else {
            if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;
        }
    }
#endif
    
    if (not_on_tty) {
        ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
             current_entry, queued_paths, unique_crashes);
        fflush(stdout);
    }
    
    // 初始化和预处理
    if (init_and_preprocess(argv, &ctx) != 0) {
        goto abandon_entry;
    }
    
    // 校准阶段
    if (handle_calibration(argv, &ctx) != 0) {
        goto abandon_entry;
    }
    
    // 修剪阶段
    if (handle_trimming(argv, &ctx) != 0) {
        goto abandon_entry;
    }
    
    // 计算性能分数
    ctx.orig_perf = ctx.perf_score = calculate_score(queue_cur);
    
    // 确定性模糊测试阶段
    if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det) {
        goto havoc_stage;
    }
    
    // 检查是否在master实例范围内
    if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1) {
        goto havoc_stage;
    }
    
    doing_det = 1;
    
    // 位翻转阶段
    if (fuzz_bitflip_stages(argv, &ctx) != 0) {
        goto abandon_entry;
    }
    
    // 算术运算阶段
    if (fuzz_arithmetic_stages(argv, &ctx) != 0) {
        goto abandon_entry;
    }
    
    // 特殊值阶段
    if (fuzz_interesting_stages(argv, &ctx) != 0) {
        goto abandon_entry;
    }
    
    // 字典阶段
    if (fuzz_dictionary_stages(argv, &ctx) != 0) {
        goto abandon_entry;
    }
    
    // 标记确定性测试完成
    if (!queue_cur->passed_det) mark_as_det_done(queue_cur);
    
havoc_stage:
    
    // Havoc 随机变异阶段 - 传递doing_det状态
    if (fuzz_havoc_stage(argv, &ctx, 0, doing_det) != 0) {
        goto abandon_entry;
    }
    
#ifndef IGNORE_FINDS
    // 拼接阶段
    if (fuzz_splice_stage(argv, &ctx) != 0) {
        goto abandon_entry;
    }
#endif
    
    ret_val = 0;
    
abandon_entry:
    
    splicing_with = -1;
    
    // 更新pending_not_fuzzed计数
    if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
        queue_cur->was_fuzzed = 1;
        pending_not_fuzzed--;
        if (queue_cur->favored) pending_favored--;
    }
    
    cleanup_fuzz_context(&ctx);
    
    return ret_val;
}