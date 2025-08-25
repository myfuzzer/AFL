/*
   american fuzzy lop - 分叉服务器模块
   =================================

   包含分叉服务器相关函数声明
*/

#ifndef AFL_FORKSERVER_H
#define AFL_FORKSERVER_H

#include "globals.h"

/* 分叉服务器函数 */
void init_forkserver(char** argv);

#endif /* AFL_FORKSERVER_H */