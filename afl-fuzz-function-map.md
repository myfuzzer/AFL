# AFL Fuzzer Function Mapping Table

This document provides a comprehensive mapping of all functions in the afl-fuzz.c file, organized by functional categories.

## Table of Contents
- [Time & Random Utilities](#time--random-utilities)
- [Display & Formatting Functions](#display--formatting-functions)  
- [Queue Management](#queue-management)
- [Bitmap & Coverage Analysis](#bitmap--coverage-analysis)
- [File I/O & Test Case Management](#file-io--test-case-management)
- [Execution & Target Running](#execution--target-running)
- [Fuzzing Strategy Functions](#fuzzing-strategy-functions)
- [Statistics & Monitoring](#statistics--monitoring)
- [System Configuration & Setup](#system-configuration--setup)
- [Dictionary & Extras Management](#dictionary--extras-management)
- [Signal Handling & Process Control](#signal-handling--process-control)
- [Main & Initialization](#main--initialization)

---

## Time & Random Utilities

| Function | Lines | Description |
|----------|--------|-------------|
| `get_cur_time()` | 342-351 | Get current unix time in milliseconds using gettimeofday() |
| `get_cur_time_us()` | 356-365 | Get current unix time in microseconds using gettimeofday() |
| `UR()` | 371-386 | Generate pseudo-random number from 0 to limit-1, reseeds from /dev/urandom periodically |
| `shuffle_ptrs()` | 391-404 | Shuffle array of pointers using Fisher-Yates algorithm with slight bias |

---

## Display & Formatting Functions

| Function | Lines | Description |
|----------|--------|-------------|
| `DI()` | 572-623 | Format integer values with appropriate unit suffixes (k, M, G, T) using cyclic static buffers |
| `DF()` | 629-644 | Format floating-point values with appropriate precision, delegates to DI() for large values |
| `DMS()` | 650-696 | Format integer as memory size with binary unit suffixes (kB, MB, GB, TB) |
| `DTD()` | 701-719 | Format time delta between two timestamps as "X days, Y hrs, Z min, W sec" |
| `describe_op()` | 3073-3107 | Construct descriptive filename for new test case capturing mutation operation details |
| `show_stats()` | 3933-4402 | Display comprehensive fuzzer statistics screen with execution metrics and coverage info |
| `show_init_stats()` | 4406-4509 | Display initial fuzzer statistics and configuration after startup |

---

## Queue Management

| Function | Lines | Description |
|----------|--------|-------------|
| `mark_as_det_done()` | 726-741 | Mark queue entry as having completed deterministic fuzzing stages |
| `mark_as_variable()` | 747-767 | Mark queue entry as having variable execution behavior |
| `mark_as_redundant()` | 773-799 | Mark/unmark queue entry as redundant for edge coverage |
| `add_to_queue()` | 804-837 | Append new test case to fuzzing queue with metadata and update counters |
| `destroy_queue()` | 842-856 | Clean up and deallocate entire fuzzing queue linked list |
| `cull_queue()` | 1316-1370 | Remove redundant queue entries that don't contribute unique coverage |

---

## Bitmap & Coverage Analysis

| Function | Lines | Description |
|----------|--------|-------------|
| `write_bitmap()` | 863-881 | Write coverage bitmap to file for session resumption or analysis |
| `read_bitmap()` | 886-896 | Read coverage bitmap from file to resume previous fuzzing session |
| `has_new_bits()` | 907-974 | Check if execution trace contains new coverage bits, returns 1 for hit-count changes, 2 for new tuples |
| `count_bits()` | 980-1011 | Count number of set bits in coverage bitmap using population count algorithm |
| `count_bytes()` | 1015-1039 | Count number of non-zero bytes in bitmap |
| `count_non_255_bytes()` | 1041-1079 | Count bytes that are not 255 (fully saturated) in bitmap |
| `simplify_trace()` | 1081-1111, 1112-1158 | Simplify execution trace by collapsing hit counts into simpler classifications |
| `init_count_class16()` | 1160-1173 | Initialize 16-bit count classification lookup table for trace simplification |
| `classify_counts()` | 1175-1201, 1202-1227 | Classify hit counts into buckets for trace comparison |
| `minimize_bits()` | 1241-1263 | Minimize differences between two bitmaps for better trace comparison |
| `update_bitmap_score()` | 1265-1315 | Update scoring for bitmap bytes to prioritize interesting paths |

---

## File I/O & Test Case Management

| Function | Lines | Description |
|----------|--------|-------------|
| `locate_diffs()` | 541-563 | Find first and last differing bytes between two buffers for splicing |
| `write_to_testcase()` | 2508-2535 | Write test case data to temporary file for target execution |
| `write_with_gap()` | 2536-2561 | Write test case with gap/padding for specific fuzzing scenarios |
| `write_crash_readme()` | 3114-3156 | Generate README file in crashes directory with debugging instructions |
| `save_if_interesting()` | 3163-3345 | Evaluate execution result and save test case if it triggers new behavior |
| `link_or_copy()` | 2947-2978 | Create hard link or copy file depending on filesystem capabilities |
| `pivot_inputs()` | 2980-3065 | Reorganize input files from input directory to output queue structure |

---

## Execution & Target Running

| Function | Lines | Description |
|----------|--------|-------------|
| `setup_shm()` | 1371-1405 | Set up shared memory region for coverage tracking between fuzzer and target |
| `remove_shm()` | 1230-1239 | Clean up shared memory segment |
| `init_forkserver()` | 2005-2289 | Initialize fork server for efficient target execution |
| `run_target()` | 2290-2507 | Execute target program and collect coverage information |
| `check_map_coverage()` | 2726-2742 | Verify that target binary produces coverage information |
| `perform_dry_run()` | 2743-2946 | Execute initial test cases to verify target functionality |

---

## Fuzzing Strategy Functions

| Function | Lines | Description |
|----------|--------|-------------|
| `trim_case()` | 4526-4649 | Minimize test case size while preserving execution path |
| `calculate_score()` | 4746-4819 | Calculate performance score for test case to prioritize fuzzing efforts |
| `could_be_bitflip()` | 4820-4849 | Check if mutation could be result of bitflip operation |
| `could_be_arith()` | 4850-4930 | Check if mutation could be result of arithmetic operation |
| `could_be_interest()` | 4931-5002 | Check if mutation could be result of interesting value insertion |
| `common_fuzz_stuff()` | 4650-4701 | Common operations performed after each mutation (execution, analysis) |
| `choose_block_len()` | 4702-4745 | Choose appropriate block length for mutations based on file size |
| `next_p2()` | 4513-4525 | Get next power of 2 for block length calculations |
| `fuzz_one()` | 5003-6694 | Main fuzzing function implementing all mutation strategies for single test case |

---

## Statistics & Monitoring

| Function | Lines | Description |
|----------|--------|-------------|
| `find_start_position()` | 3351-3379 | Find queue position to resume fuzzing from previous session |
| `find_timeout()` | 3386-3417 | Determine appropriate timeout value from previous session |
| `write_stats_file()` | 3421-3515 | Write comprehensive statistics to file for monitoring |
| `maybe_update_plot_file()` | 3520-3553 | Update plot data file for graphing fuzzer progress |
| `get_runnable_processes()` | 3591-3638 | Get number of runnable processes for system load monitoring |

---

## System Configuration & Setup

| Function | Lines | Description |
|----------|--------|-------------|
| `bind_to_free_cpu()` | 412-532 | Bind fuzzer process to free CPU core for better performance |
| `setup_post()` | 1406-1433 | Setup post-processing handler if available |
| `setup_dirs_fds()` | 7154-7276 | Create output directories and setup file descriptors |
| `setup_stdio_file()` | 7277-7293 | Setup stdio redirection file for target |
| `check_crash_handling()` | 7294-7359 | Verify system crash handling configuration |
| `check_cpu_governor()` | 7360-7415 | Check and warn about CPU governor settings |
| `get_core_count()` | 7416-7502 | Determine number of CPU cores available |
| `fix_up_sync()` | 7503-7544 | Configure synchronization settings for parallel fuzzing |
| `check_asan_opts()` | 7552-7582 | Verify AddressSanitizer configuration |
| `detect_file_args()` | 7583-7631 | Detect file arguments in command line for input redirection |
| `setup_signal_handlers()` | 7632-7674 | Install signal handlers for graceful shutdown |
| `check_binary()` | 6874-7040 | Verify target binary and check for instrumentation |
| `fix_up_banner()` | 7041-7070 | Generate display banner for fuzzer UI |
| `check_if_tty()` | 7071-7095 | Check if running on terminal for UI adjustments |
| `check_term_size()` | 7096-7112 | Verify terminal size is adequate for UI display |

---

## Dictionary & Extras Management

| Function | Lines | Description |
|----------|--------|-------------|
| `read_testcases()` | 1434-1534 | Read initial test cases from input directory |
| `compare_extras_len()` | 1537-1540 | Compare extra dictionary entries by length |
| `compare_extras_use_d()` | 1544-1547 | Compare extra dictionary entries by usage count |
| `load_extras()` | 1691-1792 | Load user-provided dictionary file |
| `memcmp_nocase()` | 1793-1801 | Case-insensitive memory comparison |
| `maybe_add_auto()` | 1803-1908 | Add automatically discovered token to dictionary |
| `save_auto()` | 1909-1936 | Save automatically discovered tokens to file |
| `load_auto()` | 1937-1979 | Load automatically discovered tokens from previous session |
| `destroy_extras()` | 1980-2002 | Clean up and deallocate dictionary data |

---

## Signal Handling & Process Control

| Function | Lines | Description |
|----------|--------|-------------|
| `handle_stop_sig()` | 6833-6844 | Handle stop signals (SIGINT, SIGTERM) for graceful shutdown |
| `handle_skipreq()` | 6845-6852 | Handle skip request signal (SIGUSR1) |
| `handle_timeout()` | 6853-6872 | Handle alarm timeout signal (SIGALRM) |
| `handle_resize()` | 7545-7551 | Handle terminal resize signal (SIGWINCH) |
| `sync_fuzzers()` | 6695-6832 | Synchronize with other fuzzer instances in parallel fuzzing setup |

---

## Directory & File Management

| Function | Lines | Description |
|----------|--------|-------------|
| `delete_files()` | 3560-3586 | Delete files with specified prefix from directory |
| `nuke_resume_dir()` | 3644-3678 | Delete temporary resume directory |
| `maybe_delete_out_dir()` | 3684-3924 | Clean up output directory or prepare for session resume |

---

## Main & Initialization

| Function | Lines | Description |
|----------|--------|-------------|
| `usage()` | 7113-7153 | Display command-line usage information |
| `get_qemu_argv()` | 7675-7743 | Prepare command line arguments for QEMU mode |
| `save_cmdline()` | 7748-7771 | Save original command line for crash reproduction |
| `main()` | 7778-8197 | Main entry point - parse arguments, initialize fuzzer, run fuzzing loop |

---

## Function Categories Summary

- **Time & Random**: 4 functions for time handling and randomization
- **Display & Formatting**: 7 functions for UI and data presentation
- **Queue Management**: 6 functions for test case queue operations
- **Bitmap & Coverage**: 12 functions for coverage analysis and tracking
- **File I/O & Test Cases**: 7 functions for file operations and test case handling  
- **Execution & Target**: 6 functions for target program execution
- **Fuzzing Strategy**: 9 functions implementing core fuzzing algorithms
- **Statistics & Monitoring**: 5 functions for performance monitoring
- **System Configuration**: 14 functions for system setup and configuration
- **Dictionary & Extras**: 9 functions for dictionary management
- **Signal Handling**: 4 functions for process control
- **Directory & File**: 3 functions for directory management
- **Main & Initialization**: 4 functions for program initialization

**Total Functions Analyzed: 90**

## Key Fuzzing Strategies Implemented

The `fuzz_one()` function (lines 5003-6694) implements multiple fuzzing strategies:

1. **Bitflip mutations**: 1-bit, 2-bit, 4-bit, 8-bit, 16-bit, 32-bit flips
2. **Arithmetic mutations**: Add/subtract small integers with endianness handling
3. **Interesting values**: Insert boundary values, magic numbers
4. **Dictionary mutations**: User-provided and auto-discovered tokens
5. **Havoc mutations**: Random combinations of above strategies
6. **Splicing**: Combine parts of different test cases

## Architecture Overview

AFL uses a coverage-guided approach with:
- Fork server for fast execution
- Shared memory for coverage feedback
- Genetic algorithm-style test case evolution
- Deterministic and random mutation strategies
- Multi-process synchronization capabilities
- Comprehensive crash and hang detection

This analysis covers all major functions in the 8,197-line afl-fuzz.c file, providing developers and researchers with a complete understanding of AFL's internal architecture and implementation.