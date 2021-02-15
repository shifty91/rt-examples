#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

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

void ns_to_ts(int64_t ns, struct timespec *ts)
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

int64_t calculate_diff(const struct timespec *current,
                       const struct timespec *expected)
{
    const int64_t expected_ns = expected->tv_sec * NSEC_PER_SEC + expected->tv_nsec;
    const int64_t current_ns = current->tv_sec * NSEC_PER_SEC + current->tv_nsec;

    return current_ns - expected_ns;
}

static int latency_fd = -1;

void configure_cpu_latency(void)
{
    /* Avoid the CPU to enter deep sleep states */
    int32_t lat = 0;
    ssize_t ret;
    int fd;

    fd = open("/dev/cpu_dma_latency", O_RDWR);
    if (fd == -1)
        return;

    ret = write(fd, &lat, sizeof(lat));
    if (ret != sizeof(lat)) {
        close(latency_fd);
        return;
    }

    latency_fd = fd;
}

void restore_cpu_latency(void)
{
    if (latency_fd > 0)
        close(latency_fd);
}
