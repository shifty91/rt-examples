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
static volatile int64_t max_latency = 0;
static const long period_ns = 1000000; /* 1 ms */
static pthread_mutex_t lock;
static pthread_cond_t cond_signal;

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

static void *printer_thread(void *data)
{
    while (!stop) {
        pthread_mutex_lock(&lock);
        pthread_cond_wait(&cond_signal, &lock);
        pthread_mutex_unlock(&lock);
        printf("Max latency: %05ld\r", max_latency / 1000);
        fflush(stdout);
    }
    printf("                                                 \r");
    printf("Max latency: %05ld\n", max_latency / 1000);

    return NULL;
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
        struct timespec current;
        int ret;
        long long diff;

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
        if (stop)
            break;

        /* Get wakeup timestamp */
        ret = clock_gettime(CLOCK_MONOTONIC, &current);
        if (ret) {
            log_err_errno("clock_gettime() failed");
            return NULL;
        }

        /* Calculate difference and maybe wakeup printing thread */
        diff = calculate_diff(&current, &time);
        if (diff > max_latency) {
            max_latency = diff;
            pthread_cond_broadcast(&cond_signal);
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    struct sched_param param;
    pthread_attr_t attr;
    pthread_t thread1, thread2;
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

    /* Setup signalling mechanism */
    ret = pthread_mutex_init(&lock, NULL);
    if (ret)
        pthread_err(ret, "pthread_mutex_init() failed");

    ret = pthread_cond_init(&cond_signal, NULL);
    if (ret)
        pthread_err(ret, "pthread_cond_init() failed");

    /* Start printing thread */
    ret = pthread_create(&thread2, NULL, printer_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    /* Setup CPU latency */
    configure_cpu_latency();

    /* Start RT thread */
    ret = pthread_create(&thread1, &attr, cyclic_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    /* Wait for RT thread to stop */
    pthread_join(thread1, NULL);

    /* Wait for printer thread */
    pthread_cond_signal(&cond_signal);
    pthread_join(thread2, NULL);

    /* Restore old CPU latency */
    restore_cpu_latency();

    return EXIT_SUCCESS;
}
