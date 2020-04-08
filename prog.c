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
        u32 siaddr;
        u32 giaddr; /* relay agent IP address */
        u8 chaddr[16];   /* link-layer client hardware
                          * address (MAC)
                          */
        u8 sname[64];    /* server host name (ASCIZ) */
        u8 file[128];    /* boot file name (ASCIZ) */
        u32 cookie;      /* fixed first four option
                          * bytes (99,130,83,99 dec)
                          */
} __packed;

int prog(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int ret = XDP_PASS;
	struct ethhdr *ether = data;
	void *after = (void *)ether + sizeof(*ether);

	if (after > data_end) {
		return XDP_ABORTED;
	}

	if (bpf_ntohs(ether->h_proto) == ETH_P_IP) {
    struct iphdr *inet4 = after;

    const int PROTO_UDP = 0x11;

    if ((void *)inet4 + sizeof(*inet4) > data_end) {
      return XDP_ABORTED;
    }

    if (inet4->protocol != PROTO_UDP) {
      return XDP_PASS;
    }

    struct udphdr *udp = (void *)inet4 + (inet4->ihl * 4);

    const int PORT_DHCP_SERVER = 0x43;
    const int PORT_DHCP_CLIENT = 0x44;
    int dport;

    if ((void *)udp + sizeof(*udp) > data_end) {
      return XDP_ABORTED;
    }

    dport = bpf_ntohs(udp->dest);
    if (dport != PORT_DHCP_SERVER && dport != PORT_DHCP_CLIENT) {
      bpf_trace_printk("not the right port\n");
      return XDP_PASS;
    }

    struct dhcp_packet *dhcp = (void *)udp + sizeof(*udp);
    if ((void *)udp + sizeof(*dhcp) > data_end) {
      return XDP_PASS;
    }

    // Incoming packet
    bpf_trace_printk("eth->src: %x\n", *ether->h_source);
    bpf_trace_printk("eth->dst: %x\n", *ether->h_dest);
    bpf_trace_printk("ip->src: %x\n", inet4->saddr);
    bpf_trace_printk("ip->dst: %x\n", inet4->daddr);
    bpf_trace_printk("udp->port: %d\n", udp->dest);
    bpf_trace_printk("dhcp->op: %x\n", dhcp->op);
    bpf_trace_printk("dhcp->ciaddr: %x\n", dhcp->ciaddr);
    bpf_trace_printk("dhcp->yiaddr: %x\n", dhcp->yiaddr);
    bpf_trace_printk("dhcp->siaddr: %x\n", dhcp->siaddr);
    bpf_trace_printk("dhcp->giaddr: %x\n", dhcp->giaddr);

    // Set ethernet source as destination
    for (int i = 0; i < ETH_ALEN; i++) {
      ether->h_dest[i] = ether->h_source[i];
    }

    // Set ethernet source to the server MAC (TODO da:0a:de:42:f7:7e)
    ether->h_source[0] = 0xda;
    ether->h_source[1] = 0x0a;
    ether->h_source[2] = 0xde;
    ether->h_source[3] = 0x42;
    ether->h_source[4] = 0xf7;
    ether->h_source[5] = 0x7e;

    // Set IP source to the server IP (TODO 192.168.100.1)
    inet4->saddr=bpf_htonl(0xB6A86401);

    // Set DHCP OP to Offer
    dhcp->op=0x02;

    // Switch ports
    udp->source = bpf_htons(PORT_DHCP_SERVER);
    udp->dest = bpf_htons(PORT_DHCP_CLIENT);

    // Outcoming packet
    bpf_trace_printk("eth->src: %x\n", *ether->h_source);
    bpf_trace_printk("eth->dst: %x\n", *ether->h_dest);
    bpf_trace_printk("ip->src: %x\n", inet4->saddr);
    bpf_trace_printk("ip->dst: %x\n", inet4->daddr);
    bpf_trace_printk("udp->port: %d\n", udp->dest);
    bpf_trace_printk("dhcp->op: %x\n", dhcp->op);
    bpf_trace_printk("dhcp->ciaddr: %x\n", dhcp->ciaddr);
    bpf_trace_printk("dhcp->yiaddr: %x\n", dhcp->yiaddr);
    bpf_trace_printk("dhcp->siaddr: %x\n", dhcp->siaddr);
    bpf_trace_printk("dhcp->giaddr: %x\n", dhcp->giaddr);
    // dhcpchaddr
    // dhcpopttype
    // dhcpoptmask
    // dhcpoptrouter
    // dhcpoptlease
    // dhcpoptserver
    // dhcpoptdns

    return XDP_TX;
	}

	return ret;
}
