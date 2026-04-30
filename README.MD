# MasterDnsVPN Project 🔐

## | [نسخه فارسی](https://github.com/masterking32/MasterDnsVPN/blob/main/README_FA.MD) | [English Version](https://github.com/masterking32/MasterDnsVPN/blob/main/README.MD) |

> **Personal fork** — cloned for study and experimentation. Original project by [@masterking32](https://github.com/masterking32).
> **Note to self:** Focusing on the ARQ and multipath resolver sections to understand how packet loss recovery works.
> **Study log:** The ~5–7B header overhead is achieved by stripping session metadata to a minimal sequence number + flags byte. Compare with DNSTT which encodes full KCP headers per segment.
> **TODO:** Test ARQ retransmit behavior under 30%+ simulated packet loss using `tc netem` — see if the multipath duplication actually compensates or just doubles congestion.
> **Progress note (2025-07):** Started `tc netem` tests at 30% loss — initial results suggest duplication helps throughput but does increase overall DNS query volume noticeably (~1.8×). Need to test at 50% to find the crossover point where duplication becomes counterproductive.
> **Progress note (2025-07, update):** Ran 50% loss tests — duplication still helps marginally at 50% (~1.15× throughput gain) but the query volume jumps to ~2.6×. Crossover point appears to be somewhere around 55–60% loss. Will try disabling duplication above that threshold and relying on ARQ alone.
> **Progress note (2025-07, update 2):** Confirmed crossover closer to 58% in repeated runs. Next step: look into whether ARQ retransmit timeout can be tuned down (currently feels conservative) to recover faster without duplication overhead. Also want to check if ChaCha20 vs AES has any measurable latency difference on low-power hardware (RPi 4 test pending).

**MasterDnsVPN** is a scientific and research-oriented project for carrying TCP traffic through DNS queries and responses. In broad goal, it is similar to projects such as DNSTT or SlipStream, but it follows a fundamentally different structure and implementation approach.
This system is designed around compatibility with many resolver behaviors and harsh network conditions, with the goal of preserving the highest possible stability and data delivery even in the worst cases.

### 📊 MasterDnsVPN Compared with Similar Projects

| Feature | SlipStream | DNSTT | MasterDnsVPN |
| :--- | :--- | :--- | :--- |
| Protocol type | Advanced DNS tunnel | Classic DNS tunnel | Advanced DNS tunnel / VPN |
| Transport protocol | QUIC | KCP + Noise | Custom protocol + ARQ |
| Transport header overhead | 🟠 ~24B | 🔴 ~59B | 🟢 ~5–7B<br>≈88% lower than DNSTT<br>≈71% lower than SlipStream |
| Encryption style | TLS 1.3 (inside QUIC) | Noise (Curve25519) | AES / ChaCha20 / XOR (if XOR is used: lightweight with lower security and no extra overhead) |
| Architecture | Unified (QUIC handles everything) | Multi-layered (KCP + SMUX + Noise) | 🟢 Lightweight custom design optimized for DNS |
| Speed | 🟡 High (up to ~5× faster than DNSTT) | 🔴 Medium | 🟢 Faster than others<br>Up to ~9× faster than DNSTT<br>Up to ~3.6× faster than SlipStream |
| Stability under packet loss | 🟡 Good | 🟠 Medium | 🟢 Very high (Multipath + ARQ) |
| Multi-resolver support | Yes (multipath) | ❌ | Yes — advanced (multi-resolver + duplication) |
| Resilience under heavy censorship | Good | Medium | Very strong (a core project goal) |
