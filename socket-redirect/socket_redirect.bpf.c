#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "socket_redirect.h"

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, struct sock *);
} sock_ops_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 24);
// } ring_buffer_map SEC(".maps");

// static __always_inline void output_connection_info(void *ctx, struct sock_key *key) {
//     struct connection_info conn_info = {};
//     conn_info.family = key->family;
//     conn_info.sip4 = key->sip4;
//     conn_info.dip4 = key->dip4;
//     conn_info.sport = key->sport;
//     conn_info.dport = key->dport;

//     bpf_ringbuf_output(&ring_buffer_map, &conn_info, sizeof(conn_info), BPF_RB_FORCE_WAKEUP);
// }

static __always_inline void sk_extract4_key(const struct bpf_sock_ops *ops,
					    struct sock_key *key)
{
    __u32 remote_port;
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;

	key->sport = (bpf_ntohl(ops->local_port) >> 16);
	/* clang-7.1 or higher seems to think it can do a 16-bit read here
	 * which unfortunately most kernels (as of October 2019) do not
	 * support, which leads to verifier failures. Insert a READ_ONCE
	 * to make sure that a 32-bit read followed by shift is generated.
	 */
	// key->dport = READ_ONCE(ops->remote_port) >> 16;
    bpf_probe_read_kernel(&remote_port, sizeof(remote_port), &ops->remote_port);
	key->dport = remote_port >> 16;

    key->pad1 = 0;
    key->pad2 = 0;
    key->pad3 = 0;
}

static __always_inline void sk_msg_extract4_key(const struct sk_msg_md *msg,
						struct sock_key *key)
{
    __u32 remote_port;
	key->dip4 = msg->remote_ip4;
	key->sip4 = msg->local_ip4;
	key->family = 1;

	key->sport = (bpf_ntohl(msg->local_port) >> 16);
	/* clang-7.1 or higher seems to think it can do a 16-bit read here
	 * which unfortunately most kernels (as of October 2019) do not
	 * support, which leads to verifier failures. Insert a READ_ONCE
	 * to make sure that a 32-bit read followed by shift is generated.
	 */
	// key->dport = READ_ONCE(msg->remote_port) >> 16;
	bpf_probe_read_kernel(&remote_port, sizeof(remote_port), &msg->remote_port);
	key->dport = remote_port >> 16;

    key->pad1 = 0;
    key->pad2 = 0;
    key->pad3 = 0;
}

SEC("sockops")
int sock_map_update(struct bpf_sock_ops *skops) {
    struct sock_key key = {};
    // struct sock *sk;
    int op;

    // bpf_trace_printk("sockops init finish\n", sizeof("sockops init finish\n"));
    // sk = (struct sock *)skops->sk;
    // if (!sk)
    //     return 0;

    op = (int)skops->op;

    sk_extract4_key(skops, &key);

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
        // output_connection_info(skops, &key);
    } else if (op == BPF_SOCK_OPS_STATE_CB) {
        int state = skops->args[0];

        if (state == TCP_CLOSE) {
            bpf_map_delete_elem(&sock_ops_map, &key);
        }
    }

    return 0;
}

SEC("sk_msg")
int sendmsg_prog(struct sk_msg_md *msg) {
    struct sock_key key = {};
    __u64 flags = BPF_F_INGRESS;
    struct sock *sk;

    sk_msg_extract4_key(msg, &key);

    sk = bpf_map_lookup_elem(&sock_ops_map, &key);
    if (!sk) {
        // output_connection_info(msg, &key);
        return SK_PASS;
    }

    // return bpf_sk_redirect_map((struct __sk_buff *)msg->sk, &sock_ops_map, (unsigned long)&key, BPF_F_INGRESS);
    return bpf_msg_redirect_hash(msg, &sock_ops_map, &key, flags);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
