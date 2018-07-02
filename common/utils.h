#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>

/* printing */
#define err(...)                                                        \
    do {                                                                \
        _log("ERROR", 1, 0, basename(__FILE__), __LINE__, __VA_ARGS__); \
    } while (0)

#define log_err(...)                                                    \
    do {                                                                \
        _log("ERROR", 0, 0, basename(__FILE__), __LINE__, __VA_ARGS__); \
    } while (0)

#define err_errno(...)                                                  \
    do {                                                                \
        _log("ERROR", 1, 1, basename(__FILE__), __LINE__, __VA_ARGS__); \
    } while (0)

#define pthread_err(ret, ...)                   \
    do {                                        \
        errno = ret;                            \
        err_errno(__VA_ARGS__);                 \
    } while (0)

#define log_err_errno(...)                                              \
    do {                                                                \
        _log("ERROR", 0, 1, basename(__FILE__), __LINE__, __VA_ARGS__); \
    } while (0)

#define info(...)                                                       \
    do {                                                                \
        _log("INFO", 0, 0, basename(__FILE__), __LINE__, __VA_ARGS__);  \
    } while (0)

void _log(const char * restrict level, int die, int with_errno,
          const char * restrict file, int line, const char * restrict fmt, ...);

/* timing */
void increment_period(struct timespec *time, long period_ns);
long long calculate_diff(const struct timespec *current,
                         const struct timespec *expected);

#endif /* _UTILS_H_ */
