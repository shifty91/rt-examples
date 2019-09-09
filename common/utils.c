#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include "utils.h"

void _log(const char * restrict level, int die, int with_errno,
          const char * restrict file, int line, const char * restrict fmt, ...)
{
    FILE *out;
    va_list args;

    va_start(args, fmt);

    if (!strcmp(level, "ERROR"))
        out = stderr;
    else
        out = stdout;

    fprintf(out, "[%s %s:%d]: ", level, file, line);
    vfprintf(out, fmt, args);
    if (with_errno)
        fprintf(out, ": %s", strerror(errno));
    fprintf(out, "\n");
    fflush(out);

    va_end(args);

    if (die)
        exit(EXIT_FAILURE);
}

void ns_to_ts(long long ns, struct timespec *ts)
{
    ts->tv_sec  = ns / NSEC_PER_SEC;
    ts->tv_nsec = ns % NSEC_PER_SEC;
}

void increment_period(struct timespec *time, long period_ns)
{
    time->tv_nsec += period_ns;

    while (time->tv_nsec >= NSEC_PER_SEC) {
        /* timespec nsec overflow */
        time->tv_sec++;
        time->tv_nsec -= NSEC_PER_SEC;
    }
}

long long calculate_diff(const struct timespec *current,
                         const struct timespec *expected)
{
    struct timespec diff;

    /* deal with overflow */
    if (current->tv_nsec - expected->tv_nsec < 0) {
        diff.tv_sec  = current->tv_sec  - expected->tv_sec - 1;
        diff.tv_nsec = current->tv_nsec - expected->tv_nsec + NSEC_PER_SEC;
    } else {
        diff.tv_sec  = current->tv_sec  - expected->tv_sec;
        diff.tv_nsec = current->tv_nsec - expected->tv_nsec;
    }

    return diff.tv_sec * NSEC_PER_SEC + diff.tv_nsec;
}
