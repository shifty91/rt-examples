#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <poll.h>
#include <limits.h>

#include <netdb.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include "utils.h"

static struct option long_options[] = {
    { "host",      optional_argument, NULL, 'H' }, /* default: localhost */
    { "port",      optional_argument, NULL, 'P' }, /* default: 6666 */
    { "priority",  optional_argument, NULL, 'p' }, /* default: 99 */
    { "cpu",       optional_argument, NULL, 'c' }, /* default: cpu 0 */
    { "help",      no_argument,       NULL, 'h' },
    { NULL },
};

/* options */
static const char *host;
static const char *port;
static int priority;
static int cpu;

/* udp */
static int udp_socket;
static struct sockaddr_in udp_sin;

/* statistics */
struct stats {
    long long packets_received;
    long long min;
    long long max;
};
static struct stats current_stats = {
    .packets_received = 0,
    .min = LLONG_MAX,
    .max = LLONG_MIN,
};

static int close_udp_socket(void)
{
    close(udp_socket);
    return 0;
}

static int open_udp_socket(void)
{
    int res;
    int sock = -1;
    struct addrinfo *sa_head, *sa, hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family   = PF_INET;
    hints.ai_flags    = AI_ADDRCONFIG;

    res = getaddrinfo(host, port, &hints, &sa_head);
    if (res)
        err("getaddrinfo() for host %s failed: %s", host, gai_strerror(res));

    for (sa = sa_head; sa != NULL; sa = sa->ai_next) {
        sock = socket(sa->ai_family, sa->ai_socktype, sa->ai_protocol);
        if (sock < 0) {
            log_err_errno("socket() failed");
            continue;
        }

        res = bind(sock, sa->ai_addr, sa->ai_addrlen);
        if (res) {
            log_err_errno("bind() failed");
            continue;
        }

        /* Got one */
        memcpy(&udp_sin, sa->ai_addr, sa->ai_addrlen);
        udp_socket = sock;
        break;
    }

    if (!sa)
        err_errno("Lookup for host %s on service %s failed", host,
                  port);

    freeaddrinfo(sa_head);

    return 0;
}

static void *receiver_thread(void *data)
{
    while (23) {
        char buffer[1024];
        struct sockaddr_in addr;
        socklen_t addr_len;
        struct timespec ts;
        long long tx_time, diff;
        ssize_t len;
        int ret;

        /* Receive UDP package */
        len = recvfrom(udp_socket, buffer, sizeof(buffer), 0,
                       &addr, &addr_len);
        if (len == -1) {
            log_err_errno("recvfrom() failed");
            return NULL;
        }
        buffer[len] = '\0';

        /* Get current time */
        ret = clock_gettime(CLOCK_TAI, &ts);
        if (ret) {
            log_err_errno("clock_gettime() failed");
            return NULL;
        }

        /* Decode */
        ret = sscanf(buffer, "KURT: %lld", &tx_time);
        if (ret != 1) {
            log_err("Failed to decode package");
            continue;
        }

        /* Update stats */
        diff = (ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec) - tx_time;
        current_stats.packets_received++;
        if (diff < current_stats.min)
            current_stats.min = diff;
        if (diff > current_stats.max)
            current_stats.max = diff;
    }

    return NULL;
}

static void *printer_thread(void *data)
{
    struct timespec time;

    /* Get current time */
    if (clock_gettime(CLOCK_MONOTONIC, &time)) {
        log_err_errno("clock_gettime() failed");
        return NULL;
    }

    while (23) {
        int ret;

        /* Sleep until next period */
        time.tv_sec++;
        do {
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &time, NULL);
        } while (ret == EINTR);
        if (ret && ret != EINTR) {
            errno = ret;
            log_err_errno("clock_nanosleep() failed");
            return NULL;
        }

        /* Print stats */
        printf("Packets: %20lld Min: %20lld [ns] Max: %20lld [ns]\r",
               current_stats.packets_received, current_stats.min,
               current_stats.max);
        fflush(stdout);
    }

    return NULL;
}

static void set_default_parameter(void)
{
    host     = "localhost";
    port     = "6666";
    priority = 99;
    cpu      = 0;
}

static void print_parameter(void)
{
    printf("------------------------------------------\n");
    printf("Host:     %s\n", host);
    printf("Port:     %s\n", port);
    printf("Priority: %d\n", priority);
    printf("CPU:      %d\n", cpu);
    printf("------------------------------------------\n");
}

static void print_usage_and_die(void)
{
    fprintf(stderr, "usage: sub [options]\n");
    fprintf(stderr, "  -H,--host:      Remote host\n");
    fprintf(stderr, "  -P,--port:      Remote port\n");
    fprintf(stderr, "  -p,--priority:  Thread priority\n");
    fprintf(stderr, "  -c,--cpu:       CPU to run on\n");

    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    struct sched_param param;
    pthread_attr_t attr;
    pthread_t recv_thread, print_thread;
    cpu_set_t cpus;
    int ret, c;

    set_default_parameter();

    while ((c = getopt_long(argc, argv, "hH:P:p:c:",
                            long_options, NULL)) != -1) {
        switch (c) {
        case 'h':
            print_usage_and_die();
            break;
        case 'H':
            host = optarg;
            break;
        case 'P':
            port = optarg;
            break;
        case 'p':
            priority = atoi(optarg);
            break;
        case 'c':
            cpu = atoi(optarg);
            break;
        default:
            print_usage_and_die();
        }
    }
    if (priority < 0 || cpu < 0)
        print_usage_and_die();

    print_parameter();

    ret = pthread_attr_init(&attr);
    if (ret)
        pthread_err(ret, "pthread_attr_init() failed");

    ret = pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    if (ret)
        pthread_err(ret, "pthread_attr_setstacksize() failed");

    if (mlockall(MCL_CURRENT | MCL_FUTURE))
        err_errno("mlockall() failed");

    ret = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
    if (ret)
        pthread_err(ret, "pthread_attr_setschedpolicy() failed");

    param.sched_priority = priority;
    ret = pthread_attr_setschedparam(&attr, &param);
    if (ret)
        pthread_err(ret, "pthread_attr_setschedparam() failed");

    ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    if (ret)
        pthread_err(ret, "pthread_attr_setinheritsched() failed");

    CPU_ZERO(&cpus);
    CPU_SET(cpu, &cpus);
    ret = pthread_attr_setaffinity_np(&attr, sizeof(cpus), &cpus);
    if (ret)
        pthread_err(ret, "pthread_attr_setaffinity_np() failed");

    open_udp_socket();

    ret = pthread_create(&recv_thread, &attr, receiver_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    ret = pthread_create(&print_thread, NULL, printer_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    ret = pthread_setname_np(recv_thread, "EtfSubcriber");
    if (ret)
        pthread_err(ret, "pthread_setname_np() failed");

    ret = pthread_setname_np(print_thread, "EtfSubPrinter");
    if (ret)
        pthread_err(ret, "pthread_setname_np() failed");

    pthread_join(recv_thread, NULL);
    pthread_join(print_thread, NULL);

    close_udp_socket();

    return EXIT_SUCCESS;
}
