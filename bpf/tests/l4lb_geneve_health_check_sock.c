// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>
#include "lib/common.h"
#include "pktgen.h"

#define ENABLE_IPV4		1
#define ENABLE_IPV6		1

#define ENABLE_NODEPORT		1
#define ENABLE_DSR		1
#define DSR_ENCAP_IPIP		2
#define DSR_ENCAP_GENEVE	3
#define DSR_ENCAP_MODE		DSR_ENCAP_GENEVE
#define ENABLE_HEALTH_CHECK	1

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		__bpf_htons(80)

#define BACKEND_IP		v4_pod_two
#define BACKEND_PORT		__bpf_htons(8080)

#define SOCKET_COOKIE		1

#define get_socket_cookie mock_get_socket_cookie

__u64 mock_get_socket_cookie(const struct bpf_sock_addr *ctx __maybe_unused)
{
	return SOCKET_COOKIE;
}

#define get_socket_opt mock_get_socket_opt

static __always_inline __maybe_unused
int mock_get_socket_opt(void *ctx __maybe_unused, int level, int optname,
			int *optval, int optlen __maybe_unused)
{
	if (level == SOL_SOCKET && optname == SO_MARK)
		*optval = MARK_MAGIC_HEALTH;

	return 0;
}

#include "bpf_sock.c"

CHECK("xdp", "l4lb_geneve_health_check_sock")
int l4lb_geneve_health_check_sock_check(__maybe_unused struct xdp_md *ctx)
{
	struct bpf_sock_addr addr = {
		.user_ip4 = BACKEND_IP,
		.user_port = BACKEND_PORT,
		.protocol = IPPROTO_TCP,
	};
	struct lb4_health *val;
	__sock_cookie key;
	int ret;

	test_init();

	ret = cil_sock4_pre_bind(&addr);
	assert(ret == SYS_PROCEED);

	addr.user_ip4 = FRONTEND_IP;
	addr.user_port = FRONTEND_PORT;

	ret = cil_sock4_connect(&addr);
	assert(ret == SYS_PROCEED);
	assert(addr.user_ip4 == BACKEND_IP);
	assert(addr.user_port == BACKEND_PORT);

	key = get_socket_cookie(&addr);
	val = map_lookup_elem(&LB4_HEALTH_MAP, &key);
	assert(val);

	assert(val->peer.address == BACKEND_IP);
	assert(val->peer.port == BACKEND_PORT);
	assert(val->svc_addr == FRONTEND_IP);
	assert(val->svc_port == FRONTEND_PORT);

	test_finish();
}
