/*
 * Copyright (C) 2021 Kurt Kanzenbach <kurt@kmk-computers.de>
 */

#ifndef _ETF_H_
#define _ETF_H_

#include <linux/if_vlan.h>

#define STR(x)					#x
#define XSTR(x)					STR(x)
#define ETH_P_ETF				0x4242
#define ETF_DEFAULT_UDP_PORT	6666

/* See: https://elixir.bootlin.com/linux/latest/source/include/linux/if_vlan.h#L48 */

/**
 *	struct vlan_ethhdr - vlan ethernet header (ethhdr + vlan_hdr)
 *	@h_dest: destination ethernet address
 *	@h_source: source ethernet address
 *	@h_vlan_proto: ethernet protocol (always 0x8100)
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};

#endif /* _ETF_H_ */
