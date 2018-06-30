#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>              /* SCHED_DEADLINE */
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/unistd.h>

#include <sys/syscall.h>
#include <sys/mman.h>

#include "utils.h"

static volatile int stop;

/* Unfortunately glibc doesn't provide syscall wrappers for
 * sched_setattr/sched_getattr, yet! */

#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

struct sched_attr {
    __u32 size;

    __u32 sched_policy;
    __u64 sched_flags;

    /* SCHED_NORMAL, SCHED_BATCH */
    __s32 sched_nice;

    /* SCHED_FIFO, SCHED_RR */
    __u32 sched_priority;

    /* SCHED_DEADLINE (nsec) */
    __u64 sched_runtime;
    __u64 sched_deadline;
    __u64 sched_period;
};

static int sched_setattr(pid_t pid, const struct sched_attr *attr,
                         unsigned int flags)
{
    return syscall(__NR_sched_setattr, pid, attr, flags);
}

static int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size,
                         unsigned int flags)
{
    return syscall(__NR_sched_getattr, pid, attr, size, flags);
}

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

static void *deadline_thread(void *arg)
{
    struct sched_attr attr;
    int ret;
    unsigned int flags = 0;

    ret = sched_getattr(0, &attr, sizeof(attr), flags);
    if (ret) {
        log_err_errno("sched_setattr");
        return NULL;
    }

    /* 500us runtime every 1ms */
    attr.sched_policy  = SCHED_DEADLINE;
    attr.sched_runtime = 500 * 1000;
    attr.sched_period  = attr.sched_deadline = 1 * 1000 * 1000;

    ret = sched_setattr(0, &attr, flags);
    if (ret < 0) {
        log_err_errno("sched_setattr");
        return NULL;
    }

    while (!stop) {
        int i = 0;

        while (1) {
            if (++i == 50000)
                break;
        }

        sched_yield();
   }

    return NULL;
}

int main(int argc, char *argv[])
{
    pthread_attr_t attr;
    pthread_t thread1, thread2;
    int ret;

    ret = pthread_attr_init(&attr);
    if (ret)
        pthread_err(ret, "pthread_attr_init() failed");

    /* Define minimum stacksize for threads */
    ret = pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    if (ret)
        pthread_err(ret, "pthread_attr_setstacksize() failed");

    /* Lock current and future pages into RAM */
    if (mlockall(MCL_CURRENT | MCL_FUTURE))
        err_errno("mlockall() failed");

    /* Setup signals */
    setup_signals();

    /* Start RT threads */
    ret = pthread_create(&thread1, &attr, deadline_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");
    ret = pthread_create(&thread2, &attr, deadline_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    /* Wait for RT threads to stop */
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return EXIT_SUCCESS;
}
