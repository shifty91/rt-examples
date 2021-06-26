#define KBUILD_MODNAME "blub"

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "etf.h"

struct bpf_map_def SEC("maps") xsks_map = {
    .type        = BPF_MAP_TYPE_XSKMAP,
    .key_size    = sizeof(int),
    .value_size  = sizeof(int),
    .max_entries = 64,
};

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int idx = ctx->rx_queue_index;
    struct ethhdr *eth;
    struct udphdr *udp;
    struct iphdr *ip;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Check for IP or IPv6 frames */
    if (eth->h_proto != bpf_htons(ETH_P_IP) &&
        eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Check for UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udp = data + sizeof(*eth) + sizeof(*ip);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Check for correct UDP port */
    if (udp->dest != bpf_htons(ETF_DEFAULT_UDP_PORT))
        return XDP_PASS;

    /* If socket bound to rx_queue than redirect to user space */
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
