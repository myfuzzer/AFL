#include "splice_engine.h"
#include "../havoc/havoc_engine.h"

u8 fuzz_splice_stage(char** argv, fuzz_context_t* ctx) {
    
retry_splicing:
    
    if (use_splicing && ctx->splice_cycle++ < SPLICE_CYCLES &&
        queued_paths > 1 && queue_cur->len > 1) {
        
        struct queue_entry* target;
        u32 tid, split_at;
        u8* new_buf;
        s32 f_diff, l_diff, fd;
        
        // 首先，如果我们为havoc修改了in_buf，让我们清理它
        if (ctx->in_buf != ctx->orig_in) {
            ck_free(ctx->in_buf);
            ctx->in_buf = ctx->orig_in;
            ctx->len = queue_cur->len;
        }
        
        // 选择一个随机的队列项并寻找到它。不要与自己拼接
        do { tid = UR(queued_paths); } while (tid == current_entry);
        
        splicing_with = tid;
        target = queue;
        
        while (tid >= 100) { target = target->next_100; tid -= 100; }
        while (tid--) target = target->next;
        
        // 确保目标有合理的长度
        while (target && (target->len < 2 || target == queue_cur)) {
            target = target->next;
            splicing_with++;
        }
        
        if (!target) goto retry_splicing;
        
        // 将测试用例读入新缓冲区
        fd = open(target->fname, O_RDONLY);
        
        if (fd < 0) PFATAL("Unable to open '%s'", target->fname);
        
        new_buf = ck_alloc_nozero(target->len);
        
        ck_read(fd, new_buf, target->len, target->fname);
        
        close(fd);
        
        // 在第一个和最后一个不同字节之间找到合适的拼接位置
        // 如果差异只是一个字节左右，则退出
        locate_diffs(ctx->in_buf, new_buf, MIN(ctx->len, target->len), &f_diff, &l_diff);
        
        if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
            ck_free(new_buf);
            goto retry_splicing;
        }
        
        // 在第一个和最后一个不同字节之间的某处拆分
        split_at = f_diff + UR(l_diff - f_diff);
        
        // 执行拼接
        ctx->len = target->len;
        memcpy(new_buf, ctx->in_buf, split_at);
        ctx->in_buf = new_buf;
        
        ck_free(ctx->out_buf);
        ctx->out_buf = ck_alloc_nozero(ctx->len);
        memcpy(ctx->out_buf, ctx->in_buf, ctx->len);
        
        // 转到havoc阶段进行进一步的变异
        // splice阶段中doing_det始终为0（不是确定性测试）
        return fuzz_havoc_stage(argv, ctx, ctx->splice_cycle, 0);
    }
    
    return 0;
}