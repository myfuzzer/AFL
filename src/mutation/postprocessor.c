#include "mutations.h"
#include <dlfcn.h>

/* 加载后处理器（如果可用）。*/

void setup_post(void) {

  void* dh;
  u8* fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn) return;

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());

  post_handler = dlsym(dh, "afl_postprocess");
  if (!post_handler) FATAL("Symbol 'afl_postprocess' not found.");

  /* 做一个快速测试。现在段错误比以后好 =) */

  post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");

}

