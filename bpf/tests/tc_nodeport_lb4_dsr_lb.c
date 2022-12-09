// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

/* Enable CT debug output */
#undef QUIET_CT

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test*/
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_DSR

#define DSR_ENCAP_NONE		0
#define DSR_ENCAP_IPIP		1
#define DSR_ENCAP_MODE		DSR_ENCAP_NONE

#define DISABLE_LOOPBACK_LB

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY
#undef FORCE_LOCAL_POLICY_EVAL_AT_SOURCE

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_one
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_IP		v4_pod_one
#define BACKEND_PORT		__bpf_htons(8080)

#define fib_lookup mock_fib_lookup

static unsigned char client_mac[6]	= mac_one;
// this matches the default node_config.h:
static unsigned char lb_mac[6]		= { 0xce, 0x72, 0xa7, 0x03, 0x88, 0x56 };
static unsigned char backend_mac[6] 	= mac_two;

long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
		     __maybe_unused int plen, __maybe_unused __u32 flags)
{
	__bpf_memcpy_builtin(params->smac, lb_mac, sizeof(lb_mac));
	__bpf_memcpy_builtin(params->dmac, backend_mac, sizeof(backend_mac));

	return 0;
}

#define SECCTX_FROM_IPCACHE 1

#include "bpf_host.c"

#define FROM_NETDEV	0
#define TO_NETDEV	1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, client_mac, lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder, 0);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = FRONTEND_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

/* Test that sending a SVC request to a DSR remote backend gets redirected by TC,
 * and the src/dst L3/L4 get translated.
 */
SETUP("tc", "tc_nodeport_dsr_lb")
int nodeport_nat_dsr_lb_setup(struct __ctx_buff *ctx)
{
	/* Register a fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the */
	/* packet to be redirected to a neighboring node */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend */
	/* it is always backend_slot 1. Point it to backend_id 124. */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Create backend id 124 which contains the IP and port to send the */
	/* packet to. */
	struct lb4_backend backend = {
		.address = BACKEND_IP,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	map_update_elem(&LB4_BACKEND_MAP_V2, &lb_svc_value.backend_id, &backend, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = 32,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	struct remote_endpoint_info cache_value = {
		.sec_label = 112233,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	int ret;

	ret = build_packet(ctx);
	if (ret)
		return ret;

	/* Jump into the entrypoint */
	tail_call_static(ctx, &entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "tc_nodeport_dsr_lb")
int nodeport_dsr_lb_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;
	__u32 *opt;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_TX);

	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	if (memcmp(l2->h_source, client_mac, sizeof(client_mac)) != 0)
		test_fatal("l2->h_source is not correct")
	if (memcmp(l2->h_dest, backend_mac, sizeof(backend_mac)) != 0)
		test_fatal("l2->h_dest is not correct")

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != CLIENT_IP)
		test_fatal("src IP has changed");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dest IP hasn't been changed to the pod IP");

	opt = (void *)l3 + sizeof(struct iphdr);
	if ((void *)opt + 2 * sizeof(__u32) > data_end)
		test_fatal("l3 DSR option out of bounds");

	if (__bpf_ntohl(*opt) != (DSR_IPV4_OPT_32 | FRONTEND_PORT))
		test_fatal("DSR option0 is bad");
	opt++;

	if (__bpf_ntohl(*opt) != FRONTEND_IP)
		test_fatal("DSR option1 is bad");
	opt++;

	l4 = (void *)opt;

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l4->source != CLIENT_PORT)
		test_fatal("src TCP port was changed");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst TCP port incorrect");

	test_finish();
}
