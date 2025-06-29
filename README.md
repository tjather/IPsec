# Real-Time Network Encryption


This project implements a simplified version of IPsec using **eBPF (Extended Berkeley Packet Filter)** to secure UDP communication between two endpoints. By intercepting network packets at the kernel level, this system ensures encrypted message exchange via **Diffie-Hellman key exchange**, **XOR-based encryption**, and logs detailed **communication statistics**.

The solution involves real-time packet filtering, **Diffie-Hellman key exchange**, XOR encryption/decryption, and traffic statistics. In today’s digital world, secure communication is essential to protect sensitive information. This project simulates a secure UDP conversation using eBPF, where the attacker can no longer view message content between the two endpoints. 

---

## Development Environment: Multipass Setup

This project uses [Multipass](https://multipass.run) to create isolated virtual machines for secure testing.

### Step-by-Step VM Setup

```bash
# Launch the first VM
multipass launch 22.04 --name alice --disk 10G --memory 4G --cpus 2

# Launch the second VM
multipass launch 22.04 --name bob --disk 10G --memory 4G --cpus 2

# Get IP addresses
multipass info

# Open shell into each VM
multipass shell alice
multipass shell bob
```

3. Reproduce unsecured communication:

- On the hose machine:
```bash
sudo tcpdump -i <broadcast interface> udp port 12345 -A
```

- On **the frist VM**:
```bash
nc -ul 12345
```

- On **the second VM**:
```bash
nc -u -p 12345 <Alice IP> 12345
```

---

## System Components

1. **Packet Interception** via TC hooks (ingress and egress)
2. **Diffie-Hellman Key Exchange** for establishing shared secrets
3. **XOR Encryption & Decryption** on-the-fly at kernel level
4. **Statistics Logging** via `trace_pipe`

---

## 1. Packet Interception on UDP Port 12345

The eBPF program filters for UDP packets on port `12345` and processes both ingress and egress traffic. Packet payloads are logged via `bpf_printk`.

---

## 2. Secure Key Exchange (Diffie-Hellman)

- Each peer generates a random private key (`a`, `b`)
- The first message (starting with a space `" "`) is replaced by the peer’s public key
- On receiving a public key, the peer derives the shared secret

```c
shared_key = (peer_public_key ^ private_key) % p
```

---

## 3. Encryption & Decryption Logic

- **Outgoing messages** are XOR-encrypted using the shared key
- **Incoming messages** are XOR-decrypted before delivery
- This transformation occurs entirely within the kernel

---

## 4. Communication Statistics

The eBPF program logs how many messages were sent and received:

```text
Ingress count for 10.0.0.5: 3
Egress count for 10.0.0.6: 4
```

These are tracked using BPF hash maps and printed using `trace_pipe`.

---

## Usage

```bash
ecc ebpf_ipsec.c
ecli run package.json

# Enable tracing
echo 1 > /sys/kernel/debug/tracing/tracing_on
cat /sys/kernel/debug/tracing/trace_pipe
```

---

## Limitations

- Only supports UDP port 12345
- XOR encryption is insecure for real applications
- No replay protection or message integrity checks
- Not a replacement for production IPsec
