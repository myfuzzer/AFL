# AFL - 重构版
---

### 版权与许可 / Copyright & License
#### Chinese
- 版权所有 (c) 2013–2017 Google LLC。此项目包含并基于 Google 的 american fuzzy lop (AFL) 项目之源代码。
- 许可：本项目依据 Apache License, Version 2.0（“许可证”）授权发布；
- 修改自: `https://github.com/google/AFL`，保留了绝大部分的逻辑, 仅进行了代码的拆分与重构。
#### English
- Copyright (c) 2013–2017 Google LLC. This project includes and is based on source code from Google’s american fuzzy lop (AFL) project.
- Licensed under the Apache License, Version 2.0 (the “License”); you may not use this work except in compliance with the License. 
- Adapted from: `https://github.com/google/AFL`, retaining most of the original logic with only code segmentation and restructuring.

### 项目介绍

原本的 `afl-fuzz.c` 太长了, 有 8000 多行, 不便于初学者学习. 
本项目对核心的 Fuzzer 模块进行了拆解, 以及中文注释. 拆分后的每个模块平均 230 行, 便于阅读.

拆分后的主要的目录结构是:
```
src
├── analysis                # 位图 Bitmap 与覆盖率 Coverage 的实现
├── core                    # Fuzzer 的调度, 包括样本执行, 种子队列, Forkserver 等
├── io                      # 底层的文件操作与模糊测试状态记录等
├── main                    # 非常庞大的 main 文件, 模糊测试的主循环在这里
├── mutation                # 与`变异`有关的部分
│   ├── core                # 变异引擎 fuzz_one() 
│   └── engines             
│       ├── bitflip         # step 1: 位反转变异
│       ├── arithmetic      # step 2: 算数变异
│       ├── interesting     # step 3: 特殊值变异
│       ├── dictionary      # step 4: 字典变异
│       ├── havoc           # step 5: [非确定性变异] 随机大破坏变异
│       └── splice          # step 6: [非确定性变异] 输入合成(拼接)变异
├── sync                    # afl-fuzz 的 Master/Slave 模式的同步逻辑
└── utils                   # 随机数、环境检查以及时间有关的工具函数
```

### 关键逻辑

#### 代码插桩
位于 `afl-as.h` 中, 用于替换 GNU默认的 `as` 汇编器. 
编译前端(如 `gcc`) 编译得到的汇编代码(`.s` 文件) 会传递给 `afl-as`, 然后 `afl-as` 会在汇编代码上的每个基本块的入口进行插桩. 
- `__afl_setup`: 初始化共享内存等
- `__afl_forkserver`: 启动 AFL 的 Forkserver
- `__afl_maybe_log`: 被插入的"桩", 用于在共享内存的 Bitmap 上记录程序执行情况. 
    - bitmap 写入的是"边", "边"由上一个基本块地址与当前基本块地址共同决定;
        - `afl_area_ptr[cur_loc ^ prev_loc]++; prev_loc = cur_loc >> 1;`
        - 在程序执行中, A->B 和 B->A 对应的逻辑不同, 因此记录上次执行位置的时候选择右移一位, 这两个值的异或结果, 表示一条边. 
        - 在 QEMU 模式下, 基本块的地址使用 TCG 的 PC 寄存器值;
        - 在编译模式下, 编译时会为每个基本块分配一个**随机值**作为基本块的 ID: `fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32, R(MAP_SIZE));`
    - `afl_area_ptr[cur_loc ^ prev_loc]++` 这里的 `afl_area_ptr` 就是当前的 Bitmap, 在 Fuzzer 中为 `trace_bits`;


#### Bitmap
- `trace_bits`: 模糊测试过程中实时的代码执行轨迹
- `first_trace`: 第一次成功运行样本的时候, 会记录 bitmap, 用于后续的 stability 检测
    - `var_bytes`: 可变边的标记, 也是用于 stability 计算的
    - `var_byte_count = count_bytes(var_bytes)` 
- `virgin_bits`: 用于判断是否发现了新路径, `has_new_bits(virgin_bits)` 

#### 能量分配机制:

1. 偏好得分
核心函数是 `calculate_score(struct queue_entry* q)`, 默认的偏好有:
- 速度因子 `q->exec_us`, 越快得分越高
- 覆盖因子 `q->bitmap_size`, 覆盖越高得分越高
- 障碍补偿 `q->handicap`, 晚发现的路径也能给高的优先级
- 深度补偿 `q->depth`, 越深得分越高

2. 偏好种子系统
- 使用 `struct queue_entry* top_rated[MAP_SIZE];` 记录每条边的 "最优" 种子
- 对于队列中的每一个种子, 计算其偏好得分: `u64 fav_factor = q->exec_us * q->len;`, 为执行时间*种子大小. 该值越小越好
- 比较 `top_rated` 中每个 bit, 把最优的 queue 记录上去
- 将 `top_rated` 中的所有的种子标记为 `top_rated[i]->favored=1`
- 概率性选择 `queue[i]->favored` 为真的种子
- 每轮进行偏好种子选择前, 都会批量重置 `q->favored = 0; q = q->next;`
- `top_rated[i]->favored` 会在每次 `cull_queue()` 时随队列整体重置并重算。

3. 能量调整系统
在Havoc阶段，如果发现新路径会动态增加能量：
```c
if (queued_paths != havoc_queued) {
    if (perf_score <= HAVOC_MAX_MULT * 100) {
        stage_max *= 2;    // 变异次数翻倍
        perf_score *= 2;   // 性能分数翻倍
    }
}
```

### 种子校正
主要是 `calibrate_case()`
1. 用于:
- 稳定性校正: 每个种子执行三次, 看看轨迹是否稳定
- 性能描述, 计算**平均执行时常** 与 **位图大小**, 用于能量分配
- 新路径判定: 通过 `has_new_bits(virgin_bits)` 判断标记 `q->has_new_cov`
- Favored 更新: 用于维护 `top_rated[]` 位最优种子列表, 后续在 `cull_queue()` 中计算 `q->favored`。
- 基本的运行情况检查:
    - forkserver 启动
    - 插桩检测
    - 超时检测
    - 异常/崩溃一致性检测

2. 调用时机:
- 启动空跑阶段：对初始输入进行干跑与校准（perform_dry_run()）。
- 新路径发现：save_if_interesting() 成功后进行内联校准。
- 修剪后重评：trim_case() 修改输入后再次调用以更新评分。
- 失败重试：样本 cal_failed 时有限次重校准。


### 模糊测试生命周期

1. 对于队列中的每一个种子, 都会执行一次 `fuzz_one()`
- 根据偏好(Favored)进行调度概率性的筛选
- 校正种子 `calibration`
- 裁剪种子 `trimming`
- 种子性能评分 `calculate_score(queue_cur)`
- 变异
    - 确定性变异
    - 非确定性变异
- 状态清理

2. 模糊测试主生命周期, 位于 `main()` 中
- 队列优化 `cull_queue()`
- 判断 queue 是否为队尾
    - 如果是队尾, 则增加 `queue_cycle++` 计数, 并回到起始点
- fuzz_one()
- 切换到下一个 queue

### 致谢

本项目包含并基于 Google 的 american fuzzy lop (AFL) 项目的源代码。感谢 Google 对开源社区与软件安全生态的长期贡献。

`qemu_mode` 的补丁来自 `https://github.com/blurbdust/AFL`
