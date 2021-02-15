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

#include <netdb.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/errqueue.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>

#include <arpa/inet.h>

#include "utils.h"

static struct option long_options[] = {
    { "host",        optional_argument, NULL, 'H' }, /* default: localhost */
    { "port",        optional_argument, NULL, 'P' }, /* default: 6666 */
    { "base",        optional_argument, NULL, 'b' }, /* default: now + 1m */
    { "intervall",   optional_argument, NULL, 'I' }, /* default: 1ms */
    { "priority",    optional_argument, NULL, 'p' }, /* default: 99 */
    { "socket",      optional_argument, NULL, 's' }, /* default: 3 */
    { "cpu",         optional_argument, NULL, 'c' }, /* default: cpu 0 */
    { "wakeup",      optional_argument, NULL, 'w' }, /* default: 500us */
    { "max_packets", optional_argument, NULL, 'm' }, /* default: 0 */
    { "help",        no_argument,       NULL, 'h' },
    { NULL },
};

/* options */
static const char *host;
static const char *port;
static long long base_time_ns;
static long long intervall_ns;
static int priority;
static int socket_priority;
static int cpu;
static long long wakeup_time_ns;
static long long max_packets;

/* gobal */
static volatile int stop;

/* udp */
static int udp_socket;
static struct sockaddr_in udp_sin;
static struct sock_txtime sk_txtime;

/* statistics */
struct statistics {
    long long packets_sent;
    long long missed_deadline;
    long long invalid_parameter;
};
static struct statistics current_stats = {
    .packets_sent = 0,
    .missed_deadline = 0,
    .invalid_parameter = 0
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

        /* Got one */
        memcpy(&udp_sin, sa->ai_addr, sa->ai_addrlen);
        udp_socket = sock;
        break;
    }

    if (!sa)
        err_errno("Lookup for host %s on service %s failed", host,
                  port);

    freeaddrinfo(sa_head);

    res = setsockopt(udp_socket, SOL_SOCKET, SO_PRIORITY,
                     &socket_priority, sizeof(socket_priority));
    if (res)
        err_errno("setsockopt() failed");

    sk_txtime.clockid = CLOCK_TAI;
    sk_txtime.flags   = 1 << 1; /* Report errors and no deadline mode */
    res = setsockopt(udp_socket, SOL_SOCKET, SO_TXTIME,
                     &sk_txtime, sizeof(sk_txtime));
    if (res)
        err_errno("setsockopt() failed");

    return 0;
}

/* See udp_tai.c */
static int send_udp_packet(long long tx_time_ns)
{
    char payload[1024];
    char control[CMSG_SPACE(sizeof(tx_time_ns))] = { 0 };
    struct cmsghdr *cmsg;
    struct msghdr msg;
    struct iovec iov;
    ssize_t cnt;

    snprintf(payload, sizeof(payload), "KURT: %lld", tx_time_ns);
    payload[sizeof(payload) - 1] = '\0';

    iov.iov_base = payload;
    iov.iov_len  = strlen(payload);

    memset(&msg, 0, sizeof(msg));
    msg.msg_name       = &udp_sin;
    msg.msg_namelen    = sizeof(udp_sin);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = control;
    msg.msg_controllen = sizeof(control);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SO_TXTIME;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(long long));
    *((long long *)CMSG_DATA(cmsg)) = tx_time_ns;

    cnt = sendmsg(udp_socket, &msg, 0);
    if (cnt < 1) {
        log_err_errno("sendmsg() failed");
        return cnt;
    }

    current_stats.packets_sent++;

    return 0;
}

/* See udp_tai.c */
static int process_socket_error_queue(void)
{
    unsigned char msg_control[CMSG_SPACE(sizeof(struct sock_extended_err))];
    unsigned char err_buffer[sizeof(unsigned long long)];
    struct cmsghdr *cmsg;
    int res;

    struct iovec iov = {
        .iov_base = err_buffer,
        .iov_len  = sizeof(err_buffer)
    };
    struct msghdr msg = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = msg_control,
        .msg_controllen = sizeof(msg_control)
    };

    res = recvmsg(udp_socket, &msg, MSG_ERRQUEUE);
    if (res == -1) {
        log_err_errno("recvmsg() failed");
        return res;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        struct sock_extended_err *serr;
        unsigned long long tstamp = 0;

        serr = (void *)CMSG_DATA(cmsg);
        if (serr->ee_origin != SO_EE_ORIGIN_TXTIME)
            continue;

        tstamp = ((unsigned long long)serr->ee_data << 32) + serr->ee_info;

        (void)tstamp;

        switch (serr->ee_code) {
        case SO_EE_CODE_TXTIME_INVALID_PARAM:
            current_stats.invalid_parameter++;
            break;
        case SO_EE_CODE_TXTIME_MISSED:
            current_stats.missed_deadline++;
            break;
        default:
            log_err("Unknown TxTime error");
        }
    }

    return 0;
}

static void *cyclic_thread(void *data)
{
    struct timespec wakeup_time;
    long long tx_time = base_time_ns;

    /*
     * Send the first packet at base_time. That's the TxTime. In order to have
     * time for queuing the packet into the Linux' network stack, we setup our
     * wakeup time to base_time - wakeup_time.
     */
    ns_to_ts(base_time_ns - wakeup_time_ns, &wakeup_time);

    while (!stop) {
        int ret;

        do {
            ret = clock_nanosleep(CLOCK_TAI, TIMER_ABSTIME, &wakeup_time, NULL);
        } while (ret == EINTR);
        if (ret && ret != EINTR) {
            errno = ret;
            log_err_errno("clock_nanosleep() failed");
            return NULL;
        }

        /* Send the UDP packet */
        ret = send_udp_packet(tx_time);
        if (ret)
            return NULL;

        /* Sleep until next period */
        tx_time += intervall_ns;
        increment_period(&wakeup_time, intervall_ns);

        if (max_packets && max_packets == current_stats.packets_sent)
            stop = 1;
    }

    return NULL;
}

static void *error_thread(void *data)
{
    struct pollfd p_fd = { .fd = udp_socket };

    while (!stop) {
        int ret;

        /* Check for errors */
        ret = poll(&p_fd, 1, -1);
        if (ret == 1 && p_fd.revents & POLLERR)
            process_socket_error_queue();
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

    while (!stop) {
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
        printf("Packets: %20lld Missed: %20lld Invalid: %20lld\r",
               current_stats.packets_sent, current_stats.missed_deadline,
               current_stats.invalid_parameter);
        fflush(stdout);
    }

    return NULL;
}

static void set_default_parameter(void)
{
    struct timespec ts;

    host      = "localhost";
    port      = "6666";

    if (clock_gettime(CLOCK_TAI, &ts))
        err_errno("clock_gettime() failed");

    ts.tv_sec += 1 * 60;
    base_time_ns = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

    intervall_ns    = 1000000;
    priority        = 99;
    socket_priority = 3;
    cpu             = 0;
    wakeup_time_ns  = 500000;
    max_packets     = 0;
}

static void print_parameter(void)
{
    printf("------------------------------------------\n");
    printf("Host:            %s\n", host);
    printf("Port:            %s\n", port);
    printf("Base Time:       %lld [ns]\n", base_time_ns);
    printf("Intervall:       %lld [ns]\n", intervall_ns);
    printf("Priority:        %d\n", priority);
    printf("Socket Priority: %d\n", socket_priority);
    printf("CPU:             %d\n", cpu);
    printf("Wakeup Time:     %lld [ns]\n", wakeup_time_ns);
    printf("Max. Packets:    %lld\n", max_packets);
    printf("------------------------------------------\n");
}

static void print_usage_and_die(void)
{
    fprintf(stderr, "usage: etf [options]\n");
    fprintf(stderr, "  -H,--host:        Remote host\n");
    fprintf(stderr, "  -P,--port:        Remote port\n");
    fprintf(stderr, "  -b,--base:        When to start in ns in reference to CLOCK_TAI\n");
    fprintf(stderr, "  -I,--intervall:   Period in ns\n");
    fprintf(stderr, "  -p,--priority:    Thread priority\n");
    fprintf(stderr, "  -s,--socket:      Socket priority\n");
    fprintf(stderr, "  -c,--cpu:         CPU to run on\n");
    fprintf(stderr, "  -w,--wakeup:      Time to wakeup before TxTime in ns\n");
    fprintf(stderr, "  -m,--max_packets: Maximum number of packets to send\n");

    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    struct sched_param param;
    pthread_attr_t attr;
    pthread_t sender, printer, checker;
    cpu_set_t cpus;
    int ret, c;

    set_default_parameter();

    while ((c = getopt_long(argc, argv, "hH:P:b:I:p:s:c:w:m:",
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
        case 'b':
            base_time_ns = atoll(optarg);
            break;
        case 'I':
            intervall_ns = atoll(optarg);
            break;
        case 'p':
            priority = atoi(optarg);
            break;
        case 's':
            socket_priority = atoi(optarg);
            break;
        case 'c':
            cpu = atoi(optarg);
            break;
        case 'w':
            wakeup_time_ns = atoll(optarg);
            break;
        case 'm':
            max_packets = atoll(optarg);
            break;
        default:
            print_usage_and_die();
        }
    }
    if (base_time_ns < 0 || intervall_ns < 0 || priority < 0 ||
        socket_priority < 0 || cpu < 0 || wakeup_time_ns < 0 ||
        max_packets < 0)
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

    configure_cpu_latency();

    ret = pthread_create(&sender, &attr, cyclic_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    ret = pthread_create(&printer, NULL, printer_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    ret = pthread_create(&checker, NULL, error_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    ret = pthread_setname_np(sender, "EtfPublisher");
    if (ret)
        pthread_err(ret, "pthread_setname_np() failed");

    ret = pthread_setname_np(printer, "EtfPubPrinter");
    if (ret)
        pthread_err(ret, "pthread_setname_np() failed");

    ret = pthread_setname_np(checker, "EtfPubChecker");
    if (ret)
        pthread_err(ret, "pthread_setname_np() failed");

    pthread_join(sender, NULL);
    pthread_join(printer, NULL);
    pthread_join(checker, NULL);

    close_udp_socket();

    restore_cpu_latency();

    return EXIT_SUCCESS;
}
