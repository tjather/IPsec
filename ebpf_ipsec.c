// ebpf_ipsec.c
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <vmlinux.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define UDP_PROTOCOL 17
#define PORT_NUMBER 12345
#define PRIME_MODULUS 23
#define GENERATOR 5
#define MAX_MESSAGE_LENGTH 100
#define MAX_PAYLOAD_SIZE 1024
#define MAX_EXPONENT 32

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} key_maps SEC(".maps");

static __always_inline __u32 mod_exp(__u32 base, __u32 exp, __u32 mod)
{
    unsigned long long result = 1;

    if (exp > MAX_EXPONENT)
        exp = MAX_EXPONENT;
    for (__u32 i = 0; i < exp; i++) {
        result = result * base;
    }

    result = result % mod;
    return result;
}

/// @tchook {"ifindex":2, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_ingress(struct __sk_buff* ctx)
{
    void* data_end = (void*)(__u64)ctx->data_end;
    void* data = (void*)(__u64)ctx->data;
    struct ethhdr* l2;
    struct iphdr* l3;
    struct udphdr* l4;
    char* payload;
    __u32 key_private_number = 100;
    __u32 key_partner_public_key = 200;
    __u32 key_shared_key = 300;
    __u32 num_ingress_msg_key = 400;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void*)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr*)(l2 + 1);
    if ((void*)(l3 + 1) > data_end)
        return TC_ACT_OK;

    if (l3->protocol != UDP_PROTOCOL)
        return TC_ACT_OK;

    l4 = (struct udphdr*)(l3 + 1);
    if ((void*)(l4 + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(l4->source) != PORT_NUMBER)
        return TC_ACT_OK;

    payload = (char*)(l4 + 1);
    if ((void*)(payload + 4) > data_end)
        return TC_ACT_OK;

    __u32 partner_public_key;
    __u32* partner_public_key_ptr = bpf_map_lookup_elem(&key_maps, &key_partner_public_key);
    if (partner_public_key_ptr) {
        partner_public_key = *partner_public_key_ptr;
    } else {
        partner_public_key = payload[0];
        bpf_map_update_elem(&key_maps, &key_partner_public_key, &partner_public_key, BPF_NOEXIST);
    }

    bpf_printk("Partner Public Key: %u", partner_public_key);

    __u32* private_key = bpf_map_lookup_elem(&key_maps, &key_private_number);
    if (private_key) {
        __u32 shared_key = mod_exp(partner_public_key, *private_key, PRIME_MODULUS);
        bpf_map_update_elem(&key_maps, &key_shared_key, &shared_key, BPF_NOEXIST);

        bpf_printk("My private key: %u, partner public key: %u, share key: %u", *private_key, partner_public_key, shared_key);
        //  bpf_printk("My private key: %u, partner public key: %u", *private_key, partner_public_key);
    } else {
        // bpf_printk("Lookup failed");
    }

    __u32* shared_key = bpf_map_lookup_elem(&key_maps, &key_shared_key);
    if (!shared_key) {
        // bpf_printk("Ingress: No shared key found");
    } else {
        for (int i = 0; i < MAX_PAYLOAD_SIZE && &payload[i] < (char*)(data_end); i++) {
            payload[i] ^= *shared_key;
        }
    }

    __u16 tot_len = bpf_ntohs(l3->tot_len); // Total packet length in bytes
    __u8 ip_header_len = l3->ihl * 4; // IP header length in bytes
    __u16 udp_header_len = sizeof(*l4); // UDP header length in bytes
    __u16 payload_len = tot_len - ip_header_len - udp_header_len - 1; // Subtract IP header length

    bpf_printk("Direction: Ingress, payload len: %d, Message: %s", payload_len, (void*)(l4 + 1));

    __u32 ingress_number;
    __u32* ingress_number_ptr = bpf_map_lookup_elem(&key_maps, &num_ingress_msg_key);

    if (ingress_number_ptr) {
        ingress_number = *ingress_number_ptr;
        bpf_printk("Number of ingress messages received: %d", ingress_number, payload);
        ingress_number = ingress_number + 1;
        bpf_map_update_elem(&key_maps, &num_ingress_msg_key, &ingress_number, BPF_ANY);
    } else {
        ingress_number = 1;
        bpf_map_update_elem(&key_maps, &num_ingress_msg_key, &ingress_number, BPF_NOEXIST);
    }

    return TC_ACT_OK;
}

/// @tchook {"ifindex":2, "attach_point":"BPF_TC_EGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_egress(struct __sk_buff* ctx)
{
    void* data_end = (void*)(__u64)ctx->data_end;
    void* data = (void*)(__u64)ctx->data;
    struct ethhdr* l2;
    struct iphdr* l3;
    struct udphdr* l4;
    char* payload;
    __u32 key_private_number = 100;
    __u32 key_partner_public_key = 200;
    __u32 key_shared_key = 300;
    __u32 num_engress_msg_key = 500;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void*)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr*)(l2 + 1);
    if ((void*)(l3 + 1) > data_end)
        return TC_ACT_OK;

    if (l3->protocol != UDP_PROTOCOL)
        return TC_ACT_OK;

    l4 = (struct udphdr*)(l3 + 1);
    if ((void*)(l4 + 1) > data_end)
        return TC_ACT_OK;
    if (bpf_ntohs(l4->dest) != PORT_NUMBER)
        return TC_ACT_OK;

    __u32 private_number;
    __u32* private_number_ptr = bpf_map_lookup_elem(&key_maps, &key_private_number);

    if (private_number_ptr) {
        private_number = *private_number_ptr;
    } else {
        private_number = bpf_get_prandom_u32() % (PRIME_MODULUS - 1) + 1; // Random value in range [1, p-1]
        bpf_map_update_elem(&key_maps, &key_private_number, &private_number, BPF_NOEXIST);
    }

    __u32 public_key = mod_exp(GENERATOR, private_number, PRIME_MODULUS);
    bpf_printk("My public key: %u, my private key: %u", public_key, private_number);

    __u32* partner_public_key = bpf_map_lookup_elem(&key_maps, &key_partner_public_key);
    if (partner_public_key) {
        __u32 shared_key = mod_exp(*partner_public_key, private_number, PRIME_MODULUS);
        bpf_map_update_elem(&key_maps, &key_shared_key, &shared_key, BPF_NOEXIST);

        bpf_printk("My private key: %u, partner public key: %u, share key: %u", private_number, *partner_public_key, shared_key);
        //  bpf_printk("My private key: %u, partner public key: %u", *private_key, partner_public_key);
    } else {
        // bpf_printk("Lookup failed");
    }

    payload = (char*)(l4 + 1);
    if ((void*)(payload + 4) > data_end) // Ensure enough space for 4-byte public key
        return TC_ACT_OK;

    if (payload[0] == ' ') {
        payload[0] = public_key;
        payload[1] = '\n';
    } else {
        __u32* shared_key = bpf_map_lookup_elem(&key_maps, &key_shared_key);
        if (!shared_key) {
            // bpf_printk("Egress: No shared key found");
            return TC_ACT_OK;
        }

        for (int i = 0; i < MAX_PAYLOAD_SIZE && &payload[i] < (char*)(data_end); i++) {
            payload[i] ^= *shared_key;
        }
    }

    __u16 tot_len = bpf_ntohs(l3->tot_len); // Total packet length in bytes
    __u8 ip_header_len = l3->ihl * 4; // IP header length in bytes
    __u16 udp_header_len = sizeof(*l4); // UDP header length in bytes
    __u16 payload_len = tot_len - ip_header_len - udp_header_len - 1; // Subtract IP header length

    bpf_printk("Direction: Egress, payload len: %d, Message: %s", payload_len, payload);

    __u32 egress_number;
    __u32* egress_number_ptr = bpf_map_lookup_elem(&key_maps, &num_engress_msg_key);

    if (egress_number_ptr) {
        egress_number = *egress_number_ptr;
        bpf_printk("Number of egress messages sent: %d", egress_number, payload);
        egress_number = egress_number + 1;
        bpf_map_update_elem(&key_maps, &num_engress_msg_key, &egress_number, BPF_ANY);
    } else {
        egress_number = 1;
        bpf_map_update_elem(&key_maps, &num_engress_msg_key, &egress_number, BPF_NOEXIST);
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";