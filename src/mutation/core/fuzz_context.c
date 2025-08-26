#include "fuzz_context.h"

u8 init_fuzz_context(fuzz_context_t* ctx, char** argv) {
    
    s32 fd, len;
    
    // 打开当前队列项文件
    fd = open(queue_cur->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);
    
    len = queue_cur->len;
    
    // 映射输入文件
    ctx->orig_in = ctx->in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (ctx->orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);
    
    close(fd);
    
    // 分配输出缓冲区
    ctx->out_buf = ck_alloc_nozero(len);
    
    // 初始化基本参数
    ctx->len = len;
    ctx->temp_len = len;
    ctx->eff_cnt = 1;
    ctx->eff_map = 0;
    ctx->a_len = 0;
    ctx->splice_cycle = 0;
    
    // 复制输入到输出缓冲区
    memcpy(ctx->out_buf, ctx->in_buf, len);
    
    // 计算性能分数
    ctx->orig_perf = ctx->perf_score = calculate_score(queue_cur);
    
    return 0;
}

void cleanup_fuzz_context(fuzz_context_t* ctx) {
    
    // 首先处理 in_buf - 需要在 orig_in 被 munmap 之前进行比较
    if (ctx->in_buf && ctx->in_buf != ctx->orig_in) {
        ck_free(ctx->in_buf);
        ctx->in_buf = NULL;
    }
    
    // 然后 munmap 原始输入缓冲区
    if (ctx->orig_in) {
        munmap(ctx->orig_in, queue_cur->len);
        ctx->orig_in = NULL;
    }
    
    // 清理输出缓冲区
    if (ctx->out_buf) {
        ck_free(ctx->out_buf);
        ctx->out_buf = NULL;
    }
    
    // 清理效应图
    if (ctx->eff_map) {
        ck_free(ctx->eff_map);
        ctx->eff_map = NULL;
    }
}

u8 setup_effector_map(fuzz_context_t* ctx) {
    
    // 分配效应图内存
    ctx->eff_map = ck_alloc(EFF_ALEN(ctx->len));
    ctx->eff_map[0] = 1;
    
    if (EFF_APOS(ctx->len - 1) != 0) {
        ctx->eff_map[EFF_APOS(ctx->len - 1)] = 1;
        ctx->eff_cnt++;
    }
    
    return 0;
}