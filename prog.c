BPF_ARRAY(counter);
static void inc(int index) {
	u64 *val = counter.lookup(&index);
	if (val)
		*val += 1;
}
static void set(int index, u64 to) {
	u64 *val = counter.lookup(&index);
	if (val)
		*val = to;
}

#include "uapi/linux/if_ether.h"
#include "uapi/linux/ip.h"
#include "uapi/linux/ipv6.h"
#include "uapi/linux/udp.h"

/* Stolen from ./drivers/staging/gdm724x/gdm_lte.c ... */
struct dhcp_packet {
        u8 op;      /* BOOTREQUEST or BOOTREPLY */
        u8 htype;   /* hardware address type.
                     * 1 = 10mb ethernet
                     */
        u8 hlen;    /* hardware address length */
        u8 hops;    /* used by relay agents only */
        u32 xid;    /* unique id */
        u16 secs;   /* elapsed since client began
                     * acquisition/renewal
                     */
        u16 flags;  /* only one flag so far: */
        #define BROADCAST_FLAG 0x8000
        /* "I need broadcast replies" */
        u32 ciaddr; /* client IP (if client is in
                     * BOUND, RENEW or REBINDING state)
                     */
        u32 yiaddr; /* 'your' (client) IP address */
        /* IP address of next server to use in
         * bootstrap, returned in DHCPOFFER,
         * DHCPACK by server
         */
        u32 siaddr_nip;
        u32 gateway_nip; /* relay agent IP address */
        u8 chaddr[16];   /* link-layer client hardware
                          * address (MAC)
                          */
        u8 sname[64];    /* server host name (ASCIZ) */
        u8 file[128];    /* boot file name (ASCIZ) */
        u32 cookie;      /* fixed first four option
                          * bytes (99,130,83,99 dec)
                          */
} __packed;

static int parse_udp(struct udphdr *udp, void *data_end) {
	const int PORT_DHCP_SERVER = 0x43;
	const int PORT_DHCP_CLIENT = 0x44;
	int dport;

	if ((void *)udp + sizeof(*udp) > data_end) {
		return XDP_ABORTED;
	}

	dport = bpf_ntohs(udp->dest);
	if (dport != PORT_DHCP_SERVER && dport != PORT_DHCP_CLIENT) {
		return XDP_PASS;
	}

	inc(dport);

	return XDP_PASS;
}

static int parse_inet4(struct iphdr *inet4, void *data_end) {
	/* Find it in some header, maybe? */
	const int PROTO_UDP = 0x11;

	if ((void *)inet4 + sizeof(*inet4) > data_end) {
		return XDP_ABORTED;
	}

	if (inet4->protocol != PROTO_UDP) {
		return XDP_PASS;
	}

	return parse_udp((void *)inet4 + (inet4->ihl * 4), data_end);
}

static int parse_inet6(struct ipv6hdr *inet6) {
	return XDP_PASS;
}

int prog(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int ret = XDP_PASS;
	struct ethhdr *ether = data;
	void *after = (void *)ether + sizeof(*ether);

	if (after > data_end) {
		return XDP_ABORTED;
	}

	switch (bpf_ntohs(ether->h_proto)) {
		case ETH_P_IP:
			ret = parse_inet4(after, data_end);
			break;
		case ETH_P_IPV6:
			ret = parse_inet6(after);
			break;
	}

	return ret;
}