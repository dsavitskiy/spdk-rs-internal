#include <stddef.h>
#include <stdarg.h>
#include <spdk/log.h>

void
spdk_rs_log(int level, const char *file, const int line, const char *func,
    const char *format, va_list args);

typedef void spdk_rs_logger(int level, const char *file, const int line,
    const char *func, const char *buf, const int len);

// pointer is set from within rust to point to our logging trampoline
spdk_rs_logger *logfn = NULL;
