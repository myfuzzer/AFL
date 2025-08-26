#include "bitflip_engine.h"

u8 fuzz_bitflip_stages(char** argv, fuzz_context_t* ctx) {
    
    // 单比特翻转
    if (fuzz_bitflip_1_1(argv, ctx)) return 1;
    
    // 双比特翻转  
    if (fuzz_bitflip_2_1(argv, ctx)) return 1;
    
    // 四比特翻转
    if (fuzz_bitflip_4_1(argv, ctx)) return 1;
    
    // 设置效应图
    setup_effector_map(ctx);
    
    // 字节翻转
    if (fuzz_bitflip_8_8(argv, ctx)) return 1;
    
    // 双字节翻转
    if (fuzz_bitflip_16_8(argv, ctx)) return 1;
    
    // 四字节翻转
    if (fuzz_bitflip_32_8(argv, ctx)) return 1;
    
    return 0;
}