#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#include <sys/mman.h>

#include "utils.h"

static volatile int stop = 0;
static const long period_ns = 1000000; /* 1 ms */

static void term_handler(int sig)
{
    stop = 1;
}

static void setup_signals(void)
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = term_handler;
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL))
        err_errno("sigaction() failed");
    if (sigaction(SIGINT, &sa, NULL))
        err_errno("sigaction() failed");
}

static void *cyclic_thread(void *data)
{
    struct timespec time;

    /* Get current time */
    if (clock_gettime(CLOCK_MONOTONIC, &time)) {
        log_err_errno("clock_gettime() failed");
        return NULL;
    }

    while (!stop) {
        int ret, i = 0;

        /* Do some work */
        while (1) {
            if (++i == 50000)
                break;
        }

        /* Sleep until next period */
        increment_period(&time, period_ns);
        do {
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &time, NULL);
        } while (ret == EINTR && !stop);
        if (ret && ret != EINTR) {
            errno = ret;
            log_err_errno("clock_nanosleep() failed");
            return NULL;
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    struct sched_param param;
    pthread_attr_t attr;
    pthread_t thread;
    int ret;

    ret = pthread_attr_init(&attr);
    if (ret)
        pthread_err(ret, "pthread_attr_init() failed");

    /* Define minimum stacksize for thread */
    ret = pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    if (ret)
        pthread_err(ret, "pthread_attr_setstacksize() failed");

    /* Lock current and future pages into RAM */
    if (mlockall(MCL_CURRENT | MCL_FUTURE))
        err_errno("mlockall() failed");

    /* Set scheduling policy to SCHED_FIFO */
    ret = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
    if (ret)
        pthread_err(ret, "pthread_attr_setschedpolicy() failed");

    /* Set thread priority */
    param.sched_priority = 98;  /* Best to avoid 99 */
    ret = pthread_attr_setschedparam(&attr, &param);
    if (ret)
        pthread_err(ret, "pthread_attr_setschedparam() failed");

    /* Force thread scheduling class and priority */
    ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    if (ret)
        pthread_err(ret, "pthread_attr_setinheritsched() failed");

    /* Setup signals */
    setup_signals();

    /* Setup CPU latency */
    configure_cpu_latency();

    /* Start RT thread */
    ret = pthread_create(&thread, &attr, cyclic_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    /* Wait for RT thread to stop */
    pthread_join(thread, NULL);

    /* Restore old CPU latency */
    restore_cpu_latency();

    return EXIT_SUCCESS;
}
