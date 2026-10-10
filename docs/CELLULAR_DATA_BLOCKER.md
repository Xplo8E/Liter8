# Cellular data blocker: control plane perfect, user plane dead

iPhone 11 (`iPhone12,1` / `n104ap`) on custom iOS 27.2 `24B5099f`. Airtel India, physical SIM, home PLMN 404-45 on serving PLMN 404-49.

## The blocker

The device attaches to LTE, completes a full PS session, and is handed a routable IP and four DNS servers by the network. **Then not one inbound packet ever arrives.** Outbound packets are accepted by the interface with no errors and nothing ever replies, including the carrier's own DNS resolvers one hop inside its core.

The same SIM gets working data in another handset. Calls and SMS work, but only over IMS on WiFi.

## Evidence

**The network provisions the session completely, every time:**

```
DataContextIPActivatedDriver: activation status = 0, is_pco_present = 1,
  pDnsIPv4_addr_array_length=2, pDnsIPv6_addr_array_length=2, ip_type = 3,
  v4.ip = 100.87.63.36, apn = airtelgprs.com, cid = 0, ipv4mtu = 0
DataContextIPActivatedDriver: activation status v4.dns = 117.96.122.156
DataContextIPActivatedDriver: activation status v4.dns = 117.96.122.40
handleDataContextActivated: Activation succeeded on kDataContextBB
associateDataPath: cid = 0 mode = 0 queueSetId = 0 txFilters=0 rxFilters=0
setChannelState: IBIContextCommunicationChannelState::WAITING_FOR_START_INDICATION->STABLE
```

**The interface is up and iOS picks it** (WiFi off, so the default route is unscoped, no IFSCOPE flag):

```
pdp_ip0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1450
    inet 100.87.63.36 --> 100.87.63.36 netmask 0xffffffff
    agent domain:Cellular type:Internet flags:0x5b
    link quality: 100 (good)   link rate: 52.43 Mbps
    state rrc: 0 (idle)

default   100.87.63.36   UGScg   pdp_ip0
```

**Nothing round-trips.** Probes pinned to the interface with `IP_BOUND_IF`, 6s deadline:

```
ICMP / UDP-53 / TCP-443  -> 8.8.8.8, 1.1.1.1       all FAIL
TCP-80                   -> 17.253.144.10          FAIL
ICMP / UDP-53 / TCP-443  -> 117.96.122.156, .40    all FAIL   <- the carrier's own DNS
```

**The counters say inbound is the dead direction:**

```
15:36   Ipkts 977   Ibytes 788328   Opkts 4106
16:01   Ipkts 977   Ibytes 788328   Opkts 5021
16:47   Ipkts 977   Ibytes 788328   Opkts 5918
```

`Ipkts` has not moved from 977 in over an hour, across three separate PDN sessions and eight probe runs, while `Opkts` rose by 2000+. `Ierrs`/`Oerrs` are 0.

**The radio is alive** (live serving-cell measurements), and uplink works for signalling since the attach itself needs it:

```
WirelessRadioManagerd: setServingCellRSRP: RSRP -90 … -95 dBm
WirelessRadioManagerd: setServingCellRSRQ: RSRQ -7.5 … -13 dB
ICE IBINetRadioSignalIndCbHandle scell_rat = IBI_RAT_LTE
```

**But RRC never leaves idle** while 1200+ packets are queued, where a modem with uplink data pending should run a Service Request and go connected:

```
state rrc: 0 (idle)
RRC state: 0
RRC idle without history: using signal qual
```

### RVI packet capture correlated with a continuous RRC trace

Run on review feedback, to test whether the packets actually leave the iOS stack rather than inferring it from `Opkts`. `rvictl -s <udid>` plus `tcpdump -i rvi0`, with the probe and a 0.5s-interval RRC sampler running inside the same window.

Every packet captured on `rvi0` during the window, all 16 of them:

```
16:59:45  IP 100.87.63.36 > 117.96.122.156: ICMP echo request, seq 1
16:59:51  IP 100.87.63.36 > 117.96.122.40:  ICMP echo request, seq 1
16:59:57  IP 100.87.63.36.55007 > 117.96.122.156.53: 43981+ A? a.root-servers.net. (36)
17:00:03  IP 100.87.63.36.63285 > 117.96.122.40.53:  43981+ A? a.root-servers.net. (36)
17:00:09  IP 100.87.63.36.50828 > 117.96.122.156.443: Flags [SEW] ... + 5 x [S] at 1s
17:00:15  IP 100.87.63.36.50829 > 117.96.122.40.443:  Flags [SEW] ... + 5 x [S] at 1s
```

`tcpdump` reports **16 packets total on the interface**, so that list is the entire capture. Every one is outbound. **Not a single inbound frame of any kind.**

The RRC sampler over the same interval:

```
116 of 116 samples:  rrc: 0 (idle)
```

Counters across the window: `Opkts 6203 -> 6231`, `Ipkts 977 -> 977`, `Ibytes` unchanged.

And the only baseband traffic on the ARI control interface during those 40 seconds:

```
32  ICE IBINetRadioSignalIndCbHandle
16  IBINetRadioSignalIndCb
```

Periodic signal-strength indications and nothing else. No `IBICallPs*` data activity, no service request.

**What this establishes:** AP-side routing and packet submission are correct. The packets are well formed, carry the right source address, and show textbook SYN retransmission backoff. So the failure is not in iOS. And the modem does not initiate a Service Request across 116 consecutive samples while uplink data is pending.

**What it does not establish:** RVI records the iOS networking stack, not RF, so on its own it does not prove the packets crossed into the baseband. That question is settled separately, below.

### Baseband queue counters: the packets do cross into the modem

The AP-to-baseband transport is Converged IPC, and each `AppleConvergedIPCPDPInterface` publishes IOReport channels for its rings. Reading TX Submission against TX Completion is what separates "never reached the modem" from "reached it and nothing happened". Deltas accumulated across one probe run:

```
GROUP                SUBGROUP                     CHANNEL                 DELTA
TX Submission Queue  pdp_ip0 QSet 0xa43e0000 Q0   Doorbell Path              14
TX Submission Queue  pdp_ip0 QSet 0xa43e0000 Q0   Doorbell Path Pkt Cnt      14
TX Submission Queue  pdp_ip0 QSet 0xa43e0000 Q0   Dequeue Action             14
TX Completion Queue  pdp_ip0 QSet 0xa43e0000 Q1   Pkt Cnt                    14
TX Completion Queue  pdp_ip0 QSet 0xa43e0000 Q1   EQ Action                  11
TX Completion Queue  pdp_ip0 QSet 0xa43e0000 Q1   Request EQ Sync Path       11
RX Submission Queue                               (no movement)
RX Completion Queue                               (no movement)
```

Fourteen packets submitted, fourteen dequeued by the baseband, fourteen completed back, and nothing whatsoever on the receive side. Absolute counters on the same queue show the same pattern over the device's whole uptime: `Doorbell Path 7235`, `Doorbell Path Pkt Cnt 5469`, `Dequeue Action 5385`.

**This kills the AP-to-baseband handoff hypothesis.** The modem is pulling the packets off the ring and releasing the buffers. The transport works.

One honest limit on the word "completion": in a DMA ring, completion means the baseband took ownership and returned the buffer, not that anything was transmitted over the air. So what is proven is that the packets definitively cross the AP-to-baseband boundary, not that they were sent.

**Taken with the RRC trace, the failure is inside the baseband.** It accepts uplink user data, completes the buffers, and still never leaves RRC idle to establish a connection and transmit. Nothing on the AP side is withholding anything.

This was read with `tools/pdpreport.c`, which subscribes to the IOReport channels through `libIOReport.dylib`. It needs `com.apple.security.exception.iokit-user-client-class = IOReportUserClient`, taken from `thermalmonitord`, which is the only non-obvious part; without it `IOReportCreateSubscription` fails for every group.

**iOS thinks it is fine and silently counts the failures**, so this is not an artefact of our prober:

```
kernel: tcp connect outgoing: [...:443] interface: pdp_ip0 (skipped: 0)
webprivacyd: [C41 ... satisfied (Path is satisfied), interface: pdp_ip0, LQM: good]
mDNSResponder: SYMPTOM_DNS_NO_REPLIES
symptomsd: dnsStall_0: 24 (+1), states: Disabled,49,404,0,0,0,None,Cellular
symptomsd: setupStall_0: 33 (+1)
```

**Separate symptom, possibly related:** the IMS PDN is refused by the baseband itself, 11 cycles in 20s. `cause 261` is above the 3GPP SM range, so it is an Apple/Intel-internal code and is unidentified:

```
activateDataContext: IBICallPsStartDataCallReq response: result=-1, cause=261, cid=-1, smCause=-1
DataCallStopped: throttleType = 1, cause = 261, errorType = kErrorTypeInternal
CTServiceDisconnectionStatus: apnName=ims, activationFailure=1, rawCauseCode=261
initiateBackoff: backoffTime = 3000 msecs
```

### ARI trace: the modem acknowledges every instruction, successfully

The tracer described below was deployed and a full PDN re-establishment was captured. The sequence, decoded with names and IDs straight from this build:

```
Encode IBICallPsStopDataCallReq(3-0x103)
Decode IBICallPsDataCallStoppedIndCb(3-0x302)
Encode IBICallPsStartDataCallReq(3-0x102)
Decode IBICallPsStartDataCallRspCb(3-0x202)
Encode IBICallPsDataPathSetupReq(3-0x108)
Decode IBICallPsDataPathSetupRspCb(3-0x208)
Decode IBICallPsActivateStatusIndCb(3-0x301)
Decode IBICallPsLteAttachIndCb(3-0x30f)
```

The request carries the right APN on the wire:

```
[0] DATA.IBIFactory  id=0x0c810000 len=95     IBICallPsStartDataCallReq
  08 20 3c 00  "airtelgprs.com"
  0a 20 10 00  03 00 00 00        ip type 3, IPv4v6
  10/18/28/2e  01 00 00 00
  62 20 10 00  03 00 00 00
```

Both responses report success:

```
[1] id=0x0d010000 len=56    IBICallPsStartDataCallRspCb
  06 20 10 00  00 00 00 00        result 0
  0c 20 10 00  ff ff ff ff        -1, matching the smCause=-1 CommCenter logs

[1] id=0x0d040000 len=28    IBICallPsDataPathSetupRspCb
  06 20 10 00  00 00 00 00        result 0
```

`IBICallPsDataPathSetupReq` is the AP asking the baseband to wire up the **user plane**, and the baseband answers 0. And the modem's own activation indication reports the address it obtained:

```
[2] id=0x0d808000 len=4174  IBICallPsActivateStatusIndCb
  0a 20 60 00  03 00 00 00  64 50 92 6f  fe 80 .. 02 00 02 89 b9 66 40
               ip_type 3    100.80.146.111   link-local IPv6 only
  0c 20 94 01  "airtelgprs.com"
```

`64 50 92 6f` is 100.80.146.111, exactly what `ifconfig` showed after that cycle, so the modem and the host agree. Note `ip_type` is 3 (IPv4v6) but only a link-local IPv6 came back, never a global one.

No error appears anywhere in the data-path setup. **The modem accepts every instruction, acknowledges each with success, confirms the user-plane path is set up, reports the address it was given, continuously measures the serving cell, takes every packet off the TX ring and completes it, and still never leaves RRC idle and never receives a byte.**

### Decoding the trace

Two conventions, both derived from the capture rather than from any published source, so anyone reading these logs can work without a decoder.

**Message IDs.** `id = ((group << 10) | (msgid >> 1)) << 16`. `StartDataCallReq(3-0x102)` appears as `0x0c810000` and `DataPathSetupReq(3-0x108)` as `0x0c840000`.

**TLV framing.** Each field is `tag(1) 0x20 len(2, little endian)` followed by the value, and **`len / 4` is the value's size in bytes**. Confirmed against four different widths in one message: `0x0010` for a 4-byte int, `0x0020` for 8 bytes, `0x0050` for 20, `0x0060` for 24, `0x0194` for the 101-byte APN field.

Applying both to the activation indication gives the modem's complete view of the bearer:

```
0x02   4B   0
0x04   4B   0
0x06   4B   -1
0x08   4B   0
0x0a  24B   ip_type 3 (IPv4v6) | IPv4 | IPv6 link-local
0x0c 101B   "airtelgprs.com"
0x0e  20B   1, 3, 3, 9, 31
0x10   4B   1
0x12  72B   3, 2, 4, 7, 3, 1 then 0x3e8, 0x3e8, 0, 0x5dc, 0x12c   QoS-shaped
0x14   4B   1
0x16  20B   6
0x18   4B   3      0x1a  1      0x1c  0      0x1e  1
0x20   8B   0, 1
0x22   4B   -1     0x24  0
```

One airplane-mode cycle produced **two** complete activations of the same APN, `100.73.14.216` then `100.116.72.158`, the second being the address the interface kept. Both succeeded. Both report `ip_type` 3 while returning only a link-local IPv6, never a global one.

There is nothing in any of it that reads as a refusal.

## What we tried, and what killed each one

| Tried | Result |
|---|---|
| SIM / line / data subscription | Ruled out. Same SIM works for data in another handset. |
| Wrong or missing APN | Ruled out. `airtelgprs.com` present, correct, set as `AttachAPN`, mask 3 (IPv4v6), blank user/pass as Airtel expects. |
| WiFi winning on routing preference | Ruled out. With WiFi off `pdp_ip0` holds the **unscoped** default route and probes still fail. |
| Zombie context iOS didn't notice | Ruled out. Airplane cycle rebuilds it fully, new IP each time (`100.75.137.63` → `100.82.236.190` → `100.87.63.36`), still dead, `Ipkts` unmoved. |
| Walled garden for an unactivated device | Ruled out. The carrier's own PCO-supplied DNS servers are equally unreachable. No garden to be walled into. |
| `publicNetAllowed=0` being the gate | Ruled out. `setPublicNetAllowed:` has one caller in CommCenter, a marshaller copying a struct byte into the reply object. It reports, it does not gate. |
| Another gate in our patched CommCenter | Ruled out. CommCenter is not refusing anything; every value it reports is correct and activation returns success. |

## What is left

**Narrowed to inside the baseband.** iOS emits the packets correctly, the Converged IPC transport delivers them, the modem dequeues and completes them, and then never leaves RRC idle to transmit. Every component on the AP side does its job. Nothing is being withheld above the modem.

**Correction to an earlier version of this document.** It said the firmware "runs the baseband with calibration unsealed through the demotion path" and offered that as the likely cause. That overstates what the code does. `l8fdr.dylib` overrides three MobileGestalt answers inside libFDR so that FDR calibration unsealing is permitted; it does not place the modem in a hardware-demoted state. Whether that override has any bearing on the user plane is an open question, not a leading hypothesis. Thanks to the reviewer who read the source and caught this.

Worth researching, in order of value:

1. **Why does a modem that has accepted uplink packets never run a Service Request?** This is now the whole question. The packets are in the baseband, the buffers are completed, the radio is camped on a cell with good signal, NAS works, and RRC stays idle. Something inside the modem is accepting user-plane data and not acting on it.
2. Is the default EPS bearer actually usable from the modem's point of view, with a valid EPS bearer ID and TFT, or did it get a session the AP believes in and the modem does not? `associateDataPath: cid = 0 mode = 0 queueSetId = 0 txFilters=0 rxFilters=0` shows zero filters, which is normal for a default bearer but worth confirming against a healthy device.
3. What is `cause = 261` / `kErrorTypeInternal` from `IBICallPsStartDataCallReq`? No verified mapping exists in the public ARI definitions, and the log separately reports `smCause=-1`, so the response decoding and error translation in this build should be traced before assigning it a meaning. This is the IMS PDN, but a modem-internal error code on one PDN is worth understanding when another PDN is also failing modem-internally.
4. Does the FDR calibration-unseal override have any effect on the user plane? See the correction above; this is a question, not a hypothesis. It is now more interesting than it was, because the failure has been localised to the modem, which is the thing whose calibration is being unsealed.

ARI tracing, described below, is the way to see the modem's side of questions 1 to 3.

**Deferred deliberately:** restoring to stock and retrying the same SIM would implicate the CFW as a whole but would change many variables at once, so it would not isolate a mechanism. Current device state is being preserved until the baseband-side trace is done.

## ARI instrumentation on this build

Groundwork for question 1, done so whoever picks it up does not repeat it. Frida is deliberately not used here.

**The syslog route is much thinner on 27.2 than on the iOS versions ARIstoteles targets.** All ARI logging comes from `libARIServer.dylib` and is six format strings:

```
(%s:%d) Indication(0x%08x) for client(%s) Type(XPC) size(%zu) conn(%s)
(%s:%d) Indication(0x%08x) for client(%s) Type(GCD) size(%zu) dispq(%s:%p)
(%s:%d) Msg for client(%s) Type(%s) cid(0x%x) size(%zu) ctx(0x%08x)
(%s:%d) Msg for client(%s) Type(GCD) size(%zu) %s ctx(0x%08X)
(%s:%d) Owner(%p) data(%p) size(%zu)
(%s:%d) Received invalid message from XPC client id(%u) size(%lu), msg(%p)
```

Those log indications being forwarded to XPC clients. No payloads, no AP-to-baseband requests, no user-plane visibility. Raising `com.apple.telephony.bb`, `com.apple.telephony.abm` and `com.apple.commcenter.ari.rt.xpc` to `Debug` in `/Library/Preferences/Logging/com.apple.system.logging.plist` and restarting `logd` was tried and changed nothing, which is consistent: there is nothing more to emit. Across a full probe window the only ARI message seen is `Indication(0x25820000)`, the periodic radio-signal telemetry.

**The supported route is `Ari::LogConfig`.** `libARI.dylib` exports a logging-configuration API whose second callback receives raw message buffers:

```c
Ari::LogConfig  (unsigned int level,
                 void (*text)(unsigned int level, const char *msg),
                 void (*data)(int dir, std::string name, unsigned int msgId,
                              const void *buf, unsigned int len));
Ari::LogConfigRt(/* same signature */);
```

Direction, name, message ID, pointer and length. That is a full ARI trace through a documented entry point rather than an inline hook.

**Alternative hook points**, if `LogConfig` turns out to be gated, all taking the raw byte vector:

```
Ari::AriClientXpcProxy::forwardIndication(shared_ptr<vector<unsigned char>>)
Ari::AriClientXpcProxy::forwardResponse  (shared_ptr<vector<unsigned char>>)
Ari::AriClientGcdProxy::forwardIndication(shared_ptr<vector<unsigned char>>)
Ari::AriClientGcdProxy::forwardResponse  (shared_ptr<vector<unsigned char>>)
```

**How to get code into the right process.** `libARI.dylib` and `libARIServer.dylib` are **not files on disk**; they exist only inside the dyld shared cache, so file replacement is impossible, the same wall that blocks the VoLTE gate. However this firmware already injects `/usr/lib/l8fdr.dylib` into CommCenter and successfully hooks cache-resident code from there. Extending that dylib, or adding a sibling, is a proven in-process path needing no new mechanism.

**A tracer built on this is in the tree.** `device/fdrfix/l8ari.cpp`, compiled into the existing `l8fdr.dylib` so it needs no new `LC_LOAD_WEAK_DYLIB` in CommCenter. It installs callbacks through `Ari::LogConfig` on a delay, because CommCenter configures ARI logging during its own startup and installing from a library constructor would simply be overwritten.

The route was validated on-device *before* spending a DFU cycle on it, with a standalone binary that resolves and calls the same symbol:

```
[*] dlopen libARI.dylib -> 0x36c81f558
[*] dlsym Ari::LogConfig -> 0x25187efd8
[*] calling Ari::LogConfig(7, text_cb, data_cb)
[*] returned without crashing
```

So the mangled name is right for 24B5099f, a cache-only library is still `dlopen`-able by path, and the `std::string`-by-value parameter is ABI-compatible. Those are the three things that would otherwise have failed silently after deployment.

Because the sealed system volume costs a DFU cycle per write, everything configurable lives on the Data volume instead:

```
/var/root/.l8ari       marker and config. Absent means fully inert.
/var/root/l8ari.log    output, truncated at start, size capped.

level=<n>   verbosity passed to Ari::LogConfig   default 7
bytes=<n>   payload bytes hex dumped per message default 64, max 512
maxmb=<n>   stop writing after this many MB      default 32
delay=<n>   seconds before installing            default 15
text=0|1    also install the text callback       default 1
```

The marker is read in the constructor, so after the single deployment the loop is: write the marker, restart CommCenter so it reloads, run a probe, read the log. No further DFU cycles.

**Message definitions are extractable from this build** rather than inherited from ARIstoteles' iOS 18.3.1 database. `libARI.dylib` is 4.9 MB with 20267 ARI symbols and exports the group table directly:

```
_ARIMSGDEF_GROUPS, _ARIMSGDEF_GROUPS_SZ
Ari::MsgSet::foreach(std::function<void(const ARIMSGDEF*)>)
```

plus 36 per-group tables. The one that matters here is **`_ARIMSGDEF_GROUP03_call_ps`**, packet-switched data. Others likely relevant: `GROUP10_net_dc_ims`, `GROUP34_ice_ipc`, `GROUP08_net_rat`, `GROUP09_net_cell`. Because `foreach` is exported, the tables can be walked programmatically from inside the process instead of scraped in Ghidra.

## Odds and ends

- `Settings > About` shows `Network: Not Available` and `copyOperatorName` returns empty on every call, while registration, PLMN resolution and carrier bundle selection all succeed. Unexplained.
- `ipv4mtu = 0` in the activation result. Unknown whether that is normal.
- 788328 bytes across 977 packets *did* arrive earlier in the same boot, and carrier-prefix IPv6 autoconf addresses existed and then expired. Something traversed the user plane once. When and why it stopped is not established. The last inbound movement was +7 packets / +942 bytes between 15:28 (`Ibytes 787386`) and 15:36 (`Ibytes 788328`), which is the same window in which WiFi was switched off. Seven packets is too few to draw a conclusion from, but the coincidence is recorded rather than dropped.
- An earlier revision of this document printed `Ibytes 788328` on both the 15:28 and 15:36 rows, which made it look as though `Ipkts` had advanced with no byte change. That was a transcription error on my part, caught in review. The 15:28 value is `787386`.
- Device identifiers (IMEI, ICCID, EID, number) are omitted here deliberately. IMEI passes Luhn and MEID matches; a TAC lookup to confirm the model allocation was inconclusive.
