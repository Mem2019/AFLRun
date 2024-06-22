#ifndef _HAVE_TRACE_H
#define _HAVE_TRACE_H

#ifdef __cplusplus
#include <atomic>
using namespace std;
#else
#include <stdatomic.h>
#endif

typedef struct _trace_t {
#ifdef AFLRUN_OVERHEAD
  atomic_ullong overhead;
#endif // AFLRUN_OVERHEAD
  atomic_size_t num;
  ctx_t trace[];
} trace_t;

#endif
