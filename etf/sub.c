/*
 * Copyright (C) 2019-2021 Kurt Kanzenbach <kurt@kmk-computers.de>
 *
 * XDP code inspired by
 *  - https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/samples/bpf/xdpsock_user.c?h=v5.4-rc8
 *  - https://github.com/xdp-project/xdp-tutorial/tree/master/advanced03-AF_XDP
 *  - https://github.com/muvarov/ipxdp
 */
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

#include <net/if.h>
#include <netdb.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>

#include "rt_config.h"

#ifdef WITH_XDP
#include <linux/if_xdp.h>

#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include <bpf/libbpf.h>
#endif

#include "etf.h"
#include "utils.h"

static struct option long_options[] = {
    { "host",        optional_argument, NULL, 'H' }, /* default: localhost */
    { "port",        optional_argument, NULL, 'P' }, /* default: 6666 */
    { "interface",   optional_argument, NULL, 'i' }, /* default: eth0 */
    { "priority",    optional_argument, NULL, 'p' }, /* default: 99 */
    { "cpu",         optional_argument, NULL, 'c' }, /* default: cpu 0 */
    { "xdp",         optional_argument, NULL, 'x' }, /* default: no */
    { "raw",         no_argument,       NULL, 'r' }, /* default: UDP */
    { "skb_mode",    optional_argument, NULL, 's' }, /* default: no */
    { "queue",       optional_argument, NULL, 'q' }, /* default: 0 */
    { "break_value", optional_argument, NULL, 'B' }, /* default: 0 */
    { "base_time",   optional_argument, NULL, 'b' }, /* default: 0 */
    { "wakeup_time", optional_argument, NULL, 'w' }, /* default: 500us */
    { "interval",    optional_argument, NULL, 'I' }, /* default: 0 */
    { "help",        no_argument,       NULL, 'h' },
    { NULL },
};

/* options */
static const char *host;
static const char *port;
static const char *interface;
static int priority;
static int cpu;
static int xdp;
static int raw;
static int skb_mode;
static int queue;
static int64_t break_value_ns;
static int64_t base_time_ns;
static int64_t wakeup_time_ns;
static int64_t interval_ns;

/* gobal */
static volatile int stop;

/* udp/raw */
static int socket_fd;

/* xdp */
#ifdef WITH_XDP
#define NUM_FRAMES         (XSK_RING_CONS__DEFAULT_NUM_DESCS + XSK_RING_PROD__DEFAULT_NUM_DESCS)
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE         32

unsigned int ifindex;
struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};
struct xdpsock {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info umem;
    struct xsk_socket *xsk;
    int fd;
};
static struct xdpsock xdp_socket;
#endif

/* statistics */
struct stats {
    int64_t packets_received;
    int64_t payload_mismatch;
    int64_t cycle_mismatch;
    int64_t min;
    int64_t max;
    double avg;
};
static struct stats current_stats = {
    .packets_received = 0,
    .payload_mismatch = 0,
    .cycle_mismatch = 0,
    .min = INT64_MAX,
    .max = INT64_MIN,
    .avg = 0.0,
};

static void close_socket(void)
{
    close(socket_fd);
}

static int open_socket(void)
{
    struct addrinfo *sa_head, *sa, hints;
    int sock = -1;
    int res;

    if (!raw) {
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
            socket_fd = sock;
            break;
        }

        if (!sa)
            err_errno("Lookup for host %s on service %s failed", host,
                      port);

        freeaddrinfo(sa_head);
    } else {
        /* Open RAW socket on ETF protocol */
        sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ETF));
        if (sock < 0)
            err_errno("socket() failed");
        socket_fd = sock;
    }

    return 0;
}

static int64_t update_stats(const struct timespec *now, int64_t expected)
{
    int64_t diff;

    /* Update stats */
    diff = (now->tv_sec * NSEC_PER_SEC + now->tv_nsec) - expected;
    current_stats.packets_received++;
    current_stats.avg += diff;
    if (diff < current_stats.min)
        current_stats.min = diff;
    if (diff > current_stats.max)
        current_stats.max = diff;

    return diff;
}

static void stop_tracing(void)
{
    int ret;

    ret = system("echo 0 > /sys/kernel/debug/tracing/tracing_on");
    if (ret)
        log_err_errno("system() failed");
}

static void *receiver_thread(void *data)
{
    while (!stop) {
        int64_t tx_time, diff;
        char buffer[4096], *p;
        struct timespec ts;
        ssize_t len;
        int ret;

        /* Receive UDP/RAW frame */
        len = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                       NULL, NULL);
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
        p = buffer;
        if (raw) {
            if (len < sizeof(struct ethhdr)) {
                current_stats.payload_mismatch++;
                continue;
            }
            p += sizeof(struct ethhdr);
        }

        ret = sscanf(p, "KURT: %lld", (long long int *)&tx_time);
        if (ret != 1) {
            current_stats.payload_mismatch++;
            continue;
        }

        /* Update stats */
        diff = update_stats(&ts, tx_time);
        if (break_value_ns && diff > break_value_ns) {
            stop_tracing();
            stop = 1;
            break;
        }
    }

    return NULL;
}

#ifdef WITH_XDP
static char *parse_raw_packet(uint64_t addr, size_t len)
{
    char *packet, *payload;
    struct ethhdr *eth;
    struct udphdr *udp;
    struct iphdr *ip;
    size_t min_len = sizeof(*eth);

    if (!raw)
        min_len += sizeof(*ip) + sizeof(*udp);

    if (len <= min_len)
        return NULL;

    packet = xsk_umem__get_data(xdp_socket.umem.buffer, addr);

    eth = (struct ethhdr *)packet;
    ip  = (struct iphdr *)(packet + sizeof(*eth));
    udp = (struct udphdr *)(packet + sizeof(*eth) + sizeof(*ip));

    if (!raw) {
        if (ntohs(eth->h_proto) != ETH_P_IP ||
            ntohs(udp->dest) != atoi(port))
            return NULL;

        payload = packet + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    } else {
        if (ntohs(eth->h_proto) != ETH_P_ETF)
            return NULL;

        payload = packet + sizeof(*eth);
    }

    return payload;
}
#endif

static void *xdp_receiver_thread(void *data)
{
#ifdef WITH_XDP
    struct timespec wakeup_time;
    struct pollfd fds[1] = { 0 };

    /* poll() !? */
    fds[0].fd     = xsk_socket__fd(xdp_socket.xsk);
    fds[0].events = POLLIN;

    /* ...or better off sleeping? */
    if (base_time_ns)
        ns_to_ts(base_time_ns - wakeup_time_ns, &wakeup_time);

    while (!stop) {
        uint32_t idx_rx = 0, idx_fq = 0, len;
        int64_t tx_time = 0, diff;
        unsigned int received, i;
        struct timespec ts;
        uint64_t addr;
        char *buffer;
        int ret;

        /* So, we have to options here:
         *  1. use poll(), but that's slow :/
         *  2. Do a mixture between active and passing waiting...
         */
        if (!base_time_ns) {
            ret = poll(fds, 1, 1000);
            if (ret == 0)
                continue;
            if (ret < 0)
                err_errno("poll() failed");

            /*
             * Process packets: One at a time is enough for cyclic apps.  Just
             * be sure, that the NIC queue is correctly confgured. ethtool can
             * be used for that.
             */
            received = xsk_ring_cons__peek(&xdp_socket.rx, BATCH_SIZE, &idx_rx);
            if (!received) {
                if (xsk_ring_prod__needs_wakeup(&xdp_socket.umem.fq))
                    recvfrom(xsk_socket__fd(xdp_socket.xsk), NULL, 0,
                             MSG_DONTWAIT, NULL, NULL);
                continue;
            }
        } else {
            do {
                ret = clock_nanosleep(CLOCK_TAI, TIMER_ABSTIME, &wakeup_time,
                                      NULL);
            } while (ret && errno == EINTR);

            /* Busy busy... */
            while (23) {
                received = xsk_ring_cons__peek(&xdp_socket.rx, BATCH_SIZE, &idx_rx);

                if (!received)
                    if (xsk_ring_prod__needs_wakeup(&xdp_socket.umem.fq))
                        recvfrom(xsk_socket__fd(xdp_socket.xsk), NULL, 0,
                                 MSG_DONTWAIT, NULL, NULL);

                if (received)
                    break;
            }

            increment_period(&wakeup_time, interval_ns);
        }

        /* Get current time */
        ret = clock_gettime(CLOCK_TAI, &ts);
        if (ret) {
            log_err_errno("clock_gettime() failed");
            return NULL;
        }

        /* One packet per cycle is expected. */
        if (received != 1)
            current_stats.cycle_mismatch++;

        /* Reserve space in fill queue */
        ret = xsk_ring_prod__reserve(&xdp_socket.umem.fq, received, &idx_fq);
        while (ret != received) {
            if (ret < 0)
                err("xsk_ring_prod__reserve() failed");

            if (xsk_ring_prod__needs_wakeup(&xdp_socket.umem.fq))
                recvfrom(xsk_socket__fd(xdp_socket.xsk), NULL, 0,
                         MSG_DONTWAIT, NULL, NULL);
            ret = xsk_ring_prod__reserve(&xdp_socket.umem.fq, received, &idx_fq);
        }

        for (i = 0; i < received; ++i) {
            /* Get the packet */
            addr = xsk_ring_cons__rx_desc(&xdp_socket.rx, idx_rx)->addr;
            len  = xsk_ring_cons__rx_desc(&xdp_socket.rx, idx_rx++)->len;

            /* Move buffer back to fill queue */
            *xsk_ring_prod__fill_addr(&xdp_socket.umem.fq, idx_fq++) =
                xsk_umem__extract_addr(addr);

            /* Parse it */
            buffer = parse_raw_packet(xsk_umem__add_offset_to_addr(addr), len);
            if (!buffer) {
                current_stats.payload_mismatch++;
                continue;
            }

            /* Decode */
            ret = sscanf(buffer, "KURT: %lld", (long long int *)&tx_time);
            if (ret != 1) {
                current_stats.payload_mismatch++;
                continue;
            }

            /* Update stats */
            diff = update_stats(&ts, tx_time);
            if (break_value_ns && diff > break_value_ns) {
                stop_tracing();
                stop = 1;
                break;
            }
        }

        xsk_ring_prod__submit(&xdp_socket.umem.fq, received);
        xsk_ring_cons__release(&xdp_socket.rx, received);
    }
#endif

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
        ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &time, NULL);
        if (ret) {
            errno = ret;
            log_err_errno("clock_nanosleep() failed");
            return NULL;
        }

        /* Print stats */
        printf("Packets: %10lld CycleErr:%10lld PayloadErr:%10lld Min: %10lld [ns] Max: %10lld [ns] AVG: %10lf\r",
               (long long int)current_stats.packets_received,
               (long long int)current_stats.cycle_mismatch,
               (long long int)current_stats.payload_mismatch,
               (long long int)current_stats.min,
               (long long int)current_stats.max,
               (long long int)current_stats.avg / (double)current_stats.packets_received);
        fflush(stdout);
    }

    return NULL;
}

static void set_default_parameter(void)
{
    host           = "localhost";
    port           = XSTR(ETF_DEFAULT_UDP_PORT);
    interface      = "eth0";
    priority       = 99;
    cpu            = 0;
    xdp            = 0;
    raw            = 0;
    skb_mode       = 0;
    queue          = 0;
    break_value_ns = 0;
    base_time_ns   = 0;
    wakeup_time_ns = 500000;
    interval_ns    = 0;
}

static void print_parameter(void)
{
    printf("------------------------------------------\n");
    printf("Host:        %s\n", host);
    printf("Port:        %s\n", port);
    printf("Interface:   %s\n", interface);
    printf("Priority:    %d\n", priority);
    printf("CPU:         %d\n", cpu);
    printf("XDP:         %s\n", xdp ? "Yes" : "No");
    printf("RAW:         %s\n", raw ? "RAW" : "UDP");
    printf("SKB Mode:    %s\n", skb_mode ? "Yes" : "No");
    printf("Queue:       %d\n", queue);
    printf("Break:       %lld [ns]\n", (long long int)break_value_ns);
    printf("Base Time:   %lld [ns]\n", (long long int)base_time_ns);
    printf("Wakeup Time: %lld [ns]\n", (long long int)wakeup_time_ns);
    printf("Interval:    %lld [ns]\n", (long long int)interval_ns);
    printf("------------------------------------------\n");
}

static void print_usage_and_die(void)
{
    fprintf(stderr, "usage: sub [options]\n");
    fprintf(stderr, "  -H,--host:        Remote host\n");
    fprintf(stderr, "  -P,--port:        Remote port\n");
    fprintf(stderr, "  -i,--interface:   Remote interface\n");
    fprintf(stderr, "  -p,--priority:    Thread priority\n");
    fprintf(stderr, "  -c,--cpu:         CPU to run on\n");
    fprintf(stderr, "  -x,--xdp:         Use XDP instead of UDP sockets\n");
    fprintf(stderr, "  -r,--raw:         Use RAW Ethernet instead of UDP\n");
    fprintf(stderr, "  -s,--skb_mode:    Use SKB instead of driver mode for XDP\n");
    fprintf(stderr, "  -q,--queue:       Queue to be used for XDP\n");
    fprintf(stderr, "  -B,--break_value: Max difference where to stop tracing\n");
    fprintf(stderr, "  -b,--base_time:   Start time for ETF publisher\n");
    fprintf(stderr, "  -w,--wakeup_time: Time to start polling before base time\n");
    fprintf(stderr, "  -I,--interval:    Period of ETF publisher\n");

    exit(EXIT_SUCCESS);
}

#ifdef WITH_XDP
static inline unsigned int xdp_flags(void)
{
    return skb_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
}

static void open_xdp_socket(void)
{
    struct xsk_socket_config xsk_cfg;
    uint32_t idx;
    int ret, i;

    /* Create XDP socket */
    xsk_cfg.rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.xdp_flags    = xdp_flags();
    xsk_cfg.bind_flags   = 0;

    ret = xsk_socket__create(&xdp_socket.xsk, interface,
                             queue, xdp_socket.umem.umem, &xdp_socket.rx,
                             &xdp_socket.tx, &xsk_cfg);
    if (ret)
        err("xsk_socket__create() failed");

    /* Add some buffers */
    ret = xsk_ring_prod__reserve(&xdp_socket.umem.fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                 &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        err("xsk_ring_prod__reserve() failed");

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&xdp_socket.umem.fq, idx++) =
            i * FRAME_SIZE;

    xsk_ring_prod__submit(&xdp_socket.umem.fq,
                          XSK_RING_PROD__DEFAULT_NUM_DESCS);
}
#endif

static void close_xdp_socket(void)
{
#ifdef WITH_XDP
    xsk_socket__delete(xdp_socket.xsk);
    xsk_umem__delete(xdp_socket.umem.umem);
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags());
#endif
}

static void setup_xdp_socket(void)
{
#ifdef WITH_XDP
    int ret, prog_fd, xsks_map = 0;
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
    };
    struct xsk_umem_config cfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags          = 0,
    };
    struct bpf_object *obj;
    struct bpf_map *map;
    void *buffer = NULL;

    if (raw)
        prog_load_attr.file = "xdp_kern_raw.o";
    else
        prog_load_attr.file = "xdp_kern_udp.o";

    ret = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
    if (ret || prog_fd < 0)
        err("bpf_prog_load_xattr() failed");

    map = bpf_object__find_map_by_name(obj, "xsks_map");
    xsks_map = bpf_map__fd(map);
    if (xsks_map < 0)
        err("No xsks_map found!");

    ifindex = if_nametoindex(interface);
    if (!ifindex)
        err_errno("if_nametoindex() failed");

    /* Use XDP in conjuction with driver assisted or software mode */
    ret = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags());
    if (ret)
        err("bpf_set_link_xdp_fd() failed");

    /* Allocate user space memory for xdp frames */
    ret = posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE),
                         NUM_FRAMES * FRAME_SIZE);
    if (ret)
        err_errno("posix_memalign() failed");

    ret = xsk_umem__create(&xdp_socket.umem.umem, buffer,
                           NUM_FRAMES * FRAME_SIZE, &xdp_socket.umem.fq,
                           &xdp_socket.umem.cq, &cfg);
    if (ret)
        err("xsk_umem__create() failed");
    xdp_socket.umem.buffer = buffer;

    /* Open and bind socket */
    open_xdp_socket();
#endif
}

static void sig_handler(int signal)
{
    stop = 1;
}

static void setup_signals(void)
{
    struct sigaction sa;

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sig_handler;
    sa.sa_flags   = 0;

    if (sigaction(SIGTERM, &sa, NULL))
        err_errno("sigaction() failed");
    if (sigaction(SIGINT, &sa, NULL))
        err_errno("sigaction() failed");
}

int main(int argc, char *argv[])
{
    struct sched_param param;
    pthread_attr_t attr;
    pthread_t recv_thread, print_thread;
    cpu_set_t cpus;
    int ret, c;

    set_default_parameter();

    while ((c = getopt_long(argc, argv, "hH:P:i:p:c:xrsq:B:b:w:I:",
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
        case 'i':
            interface = optarg;
            break;
        case 'p':
            priority = atoi(optarg);
            break;
        case 'c':
            cpu = atoi(optarg);
            break;
        case 'x':
            xdp = 1;
            break;
        case 'r':
            raw = 1;
            break;
        case 's':
            skb_mode = 1;
            break;
        case 'q':
            queue = atoi(optarg);
            break;
        case 'B':
            break_value_ns = atoll(optarg);
            break;
        case 'b':
            base_time_ns = atoll(optarg);
            break;
        case 'w':
            wakeup_time_ns = atoll(optarg);
            break;
        case 'I':
            interval_ns = atoll(optarg);
            break;
        default:
            print_usage_and_die();
        }
    }
    if (priority < 0 || cpu < 0 || queue < 0 || break_value_ns < 0 ||
        base_time_ns < 0 || wakeup_time_ns < 0)
        print_usage_and_die();

#ifndef WITH_XDP
    if (xdp)
        err("No XDP support compiled in. Cannot use it.");
#endif

    if (xdp && strcmp(port, XSTR(ETF_DEFAULT_UDP_PORT)))
        err("XDP only works with the default UDP port!");

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

    if (xdp) {
        setup_xdp_socket();

        ret = pthread_create(&recv_thread, &attr, xdp_receiver_thread, NULL);
        if (ret)
            pthread_err(ret, "pthread_create() failed");
    } else {
        open_socket();

        ret = pthread_create(&recv_thread, &attr, receiver_thread, NULL);
        if (ret)
            pthread_err(ret, "pthread_create() failed");
    }

    setup_signals();

    configure_cpu_latency();

    ret = pthread_create(&print_thread, NULL, printer_thread, NULL);
    if (ret)
        pthread_err(ret, "pthread_create() failed");

    ret = pthread_setname_np(recv_thread, "EtfSubscriber");
    if (ret)
        pthread_err(ret, "pthread_setname_np() failed");

    ret = pthread_setname_np(print_thread, "EtfSubPrinter");
    if (ret)
        pthread_err(ret, "pthread_setname_np() failed");

    pthread_join(recv_thread, NULL);
    pthread_join(print_thread, NULL);

    if (xdp)
        close_xdp_socket();
    else
        close_socket();

    restore_cpu_latency();

    return EXIT_SUCCESS;
}
