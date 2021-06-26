#define KBUILD_MODNAME "blub"

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
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
    void *p = data;
    __be16 proto;

    eth = p;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Check for VLAN frames */
    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_ethhdr *veth = p;

        if ((void *)(veth + 1) > data_end)
            return XDP_PASS;

        proto = veth->h_vlan_encapsulated_proto;
        p += sizeof(*veth);
    } else {
        proto = eth->h_proto;
        p += sizeof(*eth);
    }

    /* Check for valid ETF frames */
    if (proto != bpf_htons(ETH_P_ETF))
        return XDP_PASS;

    /* If socket bound to rx_queue than redirect to user space */
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
