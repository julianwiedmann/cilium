// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4		1
#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define DSR_ENCAP_GENEVE	3
#define ENABLE_HOST_ROUTING	1

#define ENABLE_PER_PACKET_LB	1

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY
#undef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define BACKEND_IP		v4_pod_one
#define BACKEND_PORT		__bpf_htons(8080)

#define DEFAULT_IFACE		24
#define SVC_EGRESS_IFACE	25

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *backend_mac = mac_four;

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	params->ifindex = DEFAULT_IFACE;

	if (params->ipv4_src == FRONTEND_IP && params->ipv4_dst == CLIENT_IP) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)node_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
		params->ifindex = SVC_EGRESS_IFACE;

		return 0;
	}

	return 0;
}

#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == SVC_EGRESS_IFACE)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

#define SECCTX_FROM_IPCACHE 1

#include "bpf_lxc.c"

#define FROM_CONTAINER	0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

/* Test that a reply by a DSR backend
 * - doesn't get RevDNATed in from-container,
 * - is redirected to the actual egress interface (as ENABLE_HOST_ROUTING is set)
 *   (based on the FIB lookup)
 */
PKTGEN("tc", "tc_nodeport_dsr_backend_lxc")
int nodeport_dsr_backend_lxc_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)backend_mac, (__u8 *)client_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = BACKEND_IP;
	l3->daddr = CLIENT_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = BACKEND_PORT;
	l4->dest = CLIENT_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "tc_nodeport_dsr_backend_lxc")
int nodeport_dsr_backend_lxc_setup(struct __ctx_buff *ctx)
{
	/* add local backend */
	struct endpoint_info ep_value = {};

	memcpy(&ep_value.mac, (__u8 *)backend_mac, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	struct ipv4_ct_tuple lxc_ct_tuple = {
		.saddr   = BACKEND_IP,
		.daddr   = CLIENT_IP,
		.sport   = CLIENT_PORT,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_IN,
	};

	struct ct_entry lxc_ct_entry = {};

	map_update_elem(get_ct_map4(&lxc_ct_tuple), &lxc_ct_tuple, &lxc_ct_entry, BPF_ANY);

	struct ipv4_ct_tuple dsr_ct_tuple = {
		.saddr   = BACKEND_IP,
		.daddr   = CLIENT_IP,
		.sport   = CLIENT_PORT,
		.dport   = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};

	struct ct_entry dsr_ct_entry = {};
	dsr_ct_entry.dsr = 1;

	map_update_elem(get_ct_map4(&dsr_ct_tuple), &dsr_ct_tuple, &dsr_ct_entry, BPF_ANY);

	/* Add a SNAT entry for RevDNAT */
	struct ipv4_ct_tuple nat_tuple = {
		.saddr   = BACKEND_IP,
		.daddr   = CLIENT_IP,
		.sport   = BACKEND_PORT,
		.dport   = CLIENT_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};

	struct ipv4_nat_entry nat_entry = {
		.to_saddr = FRONTEND_IP,
		.to_sport = FRONTEND_PORT,
	};

	map_update_elem(&SNAT_MAPPING_IPV4, &nat_tuple, &nat_entry, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_dsr_backend_lxc")
int nodeport_dsr_backend_lxc_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)node_mac, ETH_ALEN) != 0)
		test_fatal("src MAC is not the node MAC")
	if (memcmp(l2->h_dest, (__u8 *)client_mac, ETH_ALEN) != 0)
		test_fatal("dst MAC is not the client MAC")

	if (l3->saddr != BACKEND_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP has changed");

	if (l4->source != BACKEND_PORT)
		test_fatal("src port has changed");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port has changed");

	test_finish();
}
