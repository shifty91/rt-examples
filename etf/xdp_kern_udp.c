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

struct bpf_map_def SEC("maps") xsks_map = {
    .type        = BPF_MAP_TYPE_XSKMAP,
    .key_size    = sizeof(int),
    .value_size  = sizeof(int),
    .max_entries = 64,
};

static inline int parse_ipv4(void *data, unsigned long long nh_off,
                             void *data_end)
{
    struct iphdr *iph = data + nh_off;

    if ((void *)(iph + 1) > data_end)
        return 0;

    return iph->protocol;
}

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int idx = ctx->rx_queue_index;
    unsigned int ipproto = 0;
    unsigned long long nh_off;

    /* Check if it's a UDP frame: If UDP -> Redirect to active xsk for user
     * space. If not -> pass to stack.
     */
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    if (eth->h_proto == __builtin_bswap16(ETH_P_IP))
        ipproto = parse_ipv4(data, nh_off, data_end);

    if (ipproto != IPPROTO_UDP)
        return XDP_PASS;

    /* If socket bound to rx_queue than redirect to user space */
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, 0);

    /* Else pass to Linux' network stack */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
