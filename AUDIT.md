# mitos-bluetooth — audit notes

No Rust toolchain or Bluetooth hardware was available while this was written, so **nothing here has been compiled or run
on a radio**. The first CI run is the compile check. What *was* verified: the AES/CMAC/`c1`/`s1` code against FIPS-197,
RFC 4493 and the Bluetooth Core sample data, the RFCOMM FCS against the well-known SABM/UA frames, and every canned SDP
byte array with an independent decoder (all reproduced in unit tests).

## Why CI was red
* 31 clippy errors (types, lints) and one failing test (`connect_acl` waited for the Connection Complete event at the
  wrong parameter offset, so every outgoing BR/EDR connection timed out after 5 s).
* Cargo stopped at that failure, so `discovery`, `pairing` and the new tests never ran. Two of them could not have passed.
* The mock controller reused the stack's own constants, so tests agreed with the code even where both disagreed with
  the Bluetooth spec. The bugs below were found by reading the code against the spec.

## Spec bugs fixed (would have failed on real hardware)
| Layer | Bug |
|---|---|
| HCI | 9 wrong command opcodes (Authentication Requested, Set Connection Encryption, Remote Name Request, SCO setup/accept/reject, IO Capability Reply, OOB neg reply, Read Scan Enable) — a unit test now pins every opcode to its spec value |
| HCI | ACL packet-boundary flags swapped (every packet was malformed; every received start fragment was dropped) |
| HCI | SCO packets used a 2-byte length (spec: 1 byte); UART H4 framing had the same error |
| HCI | Read Buffer Size reply parsed as 9 bytes (it is 8) so flow control never engaged; credits leaked on disconnect |
| HCI | "LE supported" read from the wrong feature bit; Write LE Host Support sent 1 parameter instead of 2 |
| HCI | Short/odd events could panic the reader thread; an event buffer replayed stale events to later waiters |
| L2CAP | Configure Response carried our CID instead of the peer's; "connection pending" answers were treated as refusal |
| SDP | Request encoding malformed (every query failed); parser could panic on hostile input |
| RFCOMM | FCS polynomial wrong (0x8C vs 0xE0), DLCI direction bit, MSC sent without its MCC header, peer's MSC never answered |
| Connection | Incoming ACL requests were treated as SCO (link type 0/1 swapped) and rejected |
| Pairing (BR/EDR) | IO capability 0x04 is invalid in HCI; numeric comparison was auto-accepted whatever the peer required |
| Pairing (LE) | Rewritten: PDU layout, `c1`/`s1` byte order and addresses, key distribution (bond was saved before EDIV/Rand arrived), 10-byte PDU slice panic |
| A2DP/AVDTP | Signal ids shifted into the wrong bits, wrong category codes (codec 0x07, delay reporting 0x08), sink endpoint test, SBC capability layout, missing SBC payload header byte, bogus extra media byte |
| AVRCP | AVCTP header missing the PID, AV/C frames mis-ordered, volume registration/response layouts wrong, key press sent without release |
| HFP | eSCO bandwidth 16000 → 8000 bytes/s, retransmission effort |

## Robustness / memory / security
* Power off now releases the controller (the kernel can take it back and `power_on` works again); threads hold `Weak`
  references so a power cycle no longer leaks a runtime. Event subscribers are bounded (1024 events). IPC requests are
  capped at 256 KiB. One name-resolution worker instead of one thread per discovered device.
* Bonds (link keys) are written 0600 in a 0700 directory with fsync + atomic rename; a corrupt file is kept as `.corrupt`.
* Unpaired devices can no longer open HID channels; `trusted_only_connect` is honoured (still open while discoverable).
* `auto_pin`/`default_pin` from the config are now used. New IPC methods: `reconnect`, `set_keyboard_leds`.
* Release profile: `opt-level = "s"`, `codegen-units = 1`, `strip = true`.

## Still needs hardware (cannot be settled by reading code)
Real controllers' firmware quirks (vendor init/patch-RAM for UART chips), HFP with a real headset, A2DP sink variants,
HID report-descriptor corner cases, LE devices that insist on Secure Connections.

## Suggested next subsystems (most valuable first)
**Bluetooth stack**
1. LE Secure Connections (P-256 ECDH + f4/f5/f6/g2): many current peripherals refuse legacy pairing.
2. LE privacy: resolve private addresses with the stored IRK (`ah()` is one AES call) + accept-list auto-connect.
3. A local SDP server with HFP-AG / A2DP-source / AVRCP records; peers often query the host before using it.
4. Adapter hotplug (netlink uevent) and rfkill integration; today only adapters present at start are used.
5. Auto-reconnect with backoff after link loss (`auto_reconnect` exists in the config but nothing enforces it).
6. Codecs: mSBC for wide-band HFP, AAC, LC3 over isochronous channels (LE Audio).
7. Power: sniff mode for idle ACL links, LE connection-parameter policy, scan duty-cycling.
8. GATT server / advertising, HID-device role, OBEX, PAN.

**OS level (what a production system around this daemon should provide)**
rfkill + uevent hotplug, firmware loader for `btusb` blobs, seccomp + minimal capabilities (CAP_NET_ADMIN/RAW only) for
this daemon, sockets under `/run` with peer-credential checks, a supervisor that restarts it, per-service memory cgroup
limits, and an HCI trace ring buffer (btmon-style) for field diagnostics.
