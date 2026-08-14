#!/bin/sh
# Fault-injection harness (spec v2.3 §16.1), v1 edition.
# Every rule tagged repro:namespace or repro:netem in kb/rules.json has its
# scenario here: a throwaway network namespace fabricates the fault and the
# harness asserts netdiag names it. Runs as root (unshare -n) or rootless
# (unshare -rn); netem scenarios skip honestly where tc/netem is unavailable.
#
# Needs: python3 + pyroute2 for namespace plumbing; tc for netem scenarios.
set -e
BIN=${BIN:-./netdiag}
BIN=$(readlink -f "$BIN")

# Scenario hygiene: the harness fabricates faults; the host's proxy
# environment must not leak into them (proxy_unreachable sets its own).
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY

if [ "$(id -u)" = 0 ]; then NS="unshare -n"; NSM="unshare -nm"; else NS="unshare -rn"; NSM="unshare -rnm"; fi
$NS true 2>/dev/null || { echo "SKIP: no usable network-namespace support"; exit 0; }

PASS=0; SKIP=0
# ONLY="rule_a rule_b" runs a subset (useful on slow CI or in time-boxed shells).
expect() { # expect <rule_id> <cmd...>
  rule=$1; shift
  if [ -n "$ONLY" ] && ! echo " $ONLY " | grep -q " $rule "; then return 0; fi
  out=$("$@" 2>&1) || true
  echo "$out" | grep -q "rule: $rule" \
    && { echo "PASS  $rule"; PASS=$((PASS+1)); } \
    || { echo "FAIL  $rule"; echo "$out"; exit 1; }
}

# mkveth <addr> <prefixlen> [gateway] [mtu] [peer_addr]
# veth pair; veth0 gets addr (+optional default route, mtu); veth1 optionally
# gets peer_addr so the kernel itself plays "gateway that answers".
mkveth() {
  cat > /tmp/netdiag_veth.py <<PY
from pyroute2 import IPRoute
ipr = IPRoute()
ipr.link('set', index=ipr.link_lookup(ifname='lo')[0], state='up')  # real machines have lo up
ipr.link('add', ifname='veth0', kind='veth', peer='veth1')
i0 = ipr.link_lookup(ifname='veth0')[0]
i1 = ipr.link_lookup(ifname='veth1')[0]
ipr.link('set', index=i1, state='up')
ipr.link('set', index=i0, state='up'${4:+, mtu=$4})
ipr.addr('add', index=i0, address='$1', prefixlen=$2)
PY
  if [ -n "$5" ]; then cat >> /tmp/netdiag_veth.py <<PY
ipr.addr('add', index=i1, address='$5', prefixlen=$2)
PY
  fi
  if [ -n "$3" ]; then cat >> /tmp/netdiag_veth.py <<PY
# oif pinned to veth0: with the peer holding an address in the same /24 the
# kernel could otherwise egress the default route via the peer side.
ipr.route('add', dst='default', gateway='$3', oif=i0)
PY
  fi
}

# ---------------------------------------------------------------- namespace tier

# L1: nothing up at all
expect link_down $NS "$BIN"

# L3: APIPA only — DHCP asked, nobody answered
mkveth 169.254.10.5 16
expect apipa_no_dhcp $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# L3: global address, no default route
mkveth 192.168.50.5 24
expect no_default_route $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# L3+L2: default route via a gateway that never answers (and never ARPs)
mkveth 192.168.50.5 24 192.168.50.1
expect gateway_unreachable $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"
expect gateway_arp_unresolved $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# L3: LAN fine, WAN dead — the peer end owns the gateway IP and answers
mkveth 192.168.50.5 24 192.168.50.1 "" 192.168.50.1
expect upstream_unreachable $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# L3: tunnel-grade MTU on the egress path
mkveth 192.168.50.5 24 192.168.50.1 1280 192.168.50.1
expect path_mtu_low $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# L3: two default routes on different interfaces
mkveth 192.168.50.5 24 192.168.50.1
cat >> /tmp/netdiag_veth.py <<'PY'
ipr.link('add', ifname='veth2', kind='veth', peer='veth3')
i2 = ipr.link_lookup(ifname='veth2')[0]
ipr.link('set', index=ipr.link_lookup(ifname='veth3')[0], state='up')
ipr.link('set', index=i2, state='up')
ipr.addr('add', index=i2, address='192.168.60.5', prefixlen=24)
ipr.route('add', dst='default', gateway='192.168.60.1', priority=200)
PY
expect default_route_conflict $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# L3: leftover tunnel adapter, down — VPN debris. (A dummy link with a
# tunnel name: creating real tuntap needs /dev/net/tun, which CI sandboxes
# lack; the collector identifies VPN adapters by name/class either way.)
cat > /tmp/netdiag_tun.py <<'PY'
from pyroute2 import IPRoute
ipr = IPRoute()
ipr.link('set', index=ipr.link_lookup(ifname='lo')[0], state='up')
ipr.link('add', ifname='wg9', kind='dummy')
PY
expect vpn_debris $NS sh -c "python3 /tmp/netdiag_tun.py && $BIN"

# L3: full tunnel — default route inside the tun
mkveth 192.168.50.5 24
cat >> /tmp/netdiag_veth.py <<'PY'
ipr.link('add', ifname='wg9', kind='dummy')
it = ipr.link_lookup(ifname='wg9')[0]
ipr.link('set', index=it, state='up')
ipr.addr('add', index=it, address='10.8.0.2', prefixlen=24)
ipr.route('add', dst='default', gateway='10.8.0.1', oif=it)
PY
expect vpn_full_tunnel $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# L3: IPv6 configured but dead — global v6 addr, no v6 route
mkveth 192.168.50.5 24
cat >> /tmp/netdiag_veth.py <<'PY'
ipr.addr('add', index=i0, address='2001:db8::5', prefixlen=64)
PY
expect ipv6_broken_dualstack $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN"

# The blame-partition tier (§8, v1.1): the same namespaces, asserting the
# verdict headline instead of a rule id.
expect_text() { # expect_text <label> <pattern> <cmd...>
  label=$1; pattern=$2; shift 2
  if [ -n "$ONLY" ] && ! echo " $ONLY " | grep -q " $label "; then return 0; fi
  out=$("$@" 2>&1) || true
  echo "$out" | grep -q "$pattern" \
    && { echo "PASS  $label"; PASS=$((PASS+1)); } \
    || { echo "FAIL  $label"; echo "$out"; exit 1; }
}

# dead gateway → the verdict blames the LAN
mkveth 192.168.50.5 24 192.168.50.1
expect_text verdict_lan "problem is inside your LAN" \
  $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN why no-internet"

# gateway answers, upstream dead → the verdict blames the ISP/WAN
mkveth 192.168.50.5 24 192.168.50.1 "" 192.168.50.1
expect_text verdict_isp "ISP/WAN side" \
  $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN why no-internet"

# The mount-namespace tier: bind-mounted /etc files inside the netns.
if $NSM true 2>/dev/null; then
  # L7: stale hosts-file override
  printf '10.9.9.9 legacy-erp.internal\n' > /tmp/netdiag_hosts
  expect hosts_file_override $NSM sh -c \
    "mount --bind /tmp/netdiag_hosts /etc/hosts && $BIN"

  # L7: no DNS servers configured at all
  : > /tmp/netdiag_empty
  expect no_dns_servers $NSM sh -c \
    "mount --bind /tmp/netdiag_empty /etc/resolv.conf && $BIN"

  # L7: resolver disagreement + hijack — two local resolvers answering
  # differently, one with a private IP for a public name (§16.1: "a resolver
  # pair configured to disagree").
  cat > /tmp/netdiag_dns.py <<'PY'
import socket, struct, sys, threading
def serve(bind_ip, answer_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((bind_ip, 53))
    while True:
        q, addr = s.recvfrom(512)
        # end of question section (skip labels + qtype/qclass); drops any
        # EDNS0 OPT record the resolver appended
        i = 12
        while q[i] != 0:
            i += q[i] + 1
        i += 5
        question = q[12:i]
        qtype = struct.unpack('!H', q[i-4:i-2])[0]
        if qtype == 1:  # A: one spoofed answer
            resp = q[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + question
            resp += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
            resp += socket.inet_aton(answer_ip)
        else:  # anything else: clean empty NOERROR
            resp = q[:2] + b'\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00' + question
        s.sendto(resp, addr)
threading.Thread(target=serve, args=('127.0.0.10', '1.2.3.4'), daemon=True).start()
threading.Thread(target=serve, args=('127.0.0.11', '10.0.0.99'), daemon=True).start()
import subprocess
sys.exit(subprocess.call(sys.argv[1:]))
PY
  printf 'nameserver 127.0.0.10\nnameserver 127.0.0.11\n' > /tmp/netdiag_resolv
  cat > /tmp/netdiag_lo.py <<'PY'
from pyroute2 import IPRoute
ipr = IPRoute()
# lo up is all that's needed: 127.0.0.0/8 is host-local in its entirety.
ipr.link('set', index=ipr.link_lookup(ifname='lo')[0], state='up')
PY
  expect resolver_disagreement $NSM sh -c \
    "mount --bind /tmp/netdiag_resolv /etc/resolv.conf && python3 /tmp/netdiag_lo.py && python3 /tmp/netdiag_dns.py $BIN"
  expect dns_hijack $NSM sh -c \
    "mount --bind /tmp/netdiag_resolv /etc/resolv.conf && python3 /tmp/netdiag_lo.py && python3 /tmp/netdiag_dns.py $BIN"

  # L7: captive portal — the 204 probe hostname pinned to a local HTTP
  # server that answers 302 (a tiny service container, §16.1).
  cat > /tmp/netdiag_portal.py <<'PY'
import http.server, socketserver, subprocess, sys, threading
class Portal(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://portal.local/login')
        self.end_headers()
    def log_message(self, *a): pass
srv = socketserver.TCPServer(('127.0.0.1', 80), Portal)
threading.Thread(target=srv.serve_forever, daemon=True).start()
sys.exit(subprocess.call(sys.argv[1:]))
PY
  printf '127.0.0.1 connectivitycheck.gstatic.com\n' > /tmp/netdiag_hosts_portal
  expect captive_portal $NSM sh -c \
    "mount --bind /tmp/netdiag_hosts_portal /etc/hosts && python3 /tmp/netdiag_lo.py && python3 /tmp/netdiag_portal.py $BIN"

  # L7: proxy configured but dead
  expect proxy_unreachable $NSM sh -c \
    "https_proxy=http://192.0.2.1:3128 $BIN"
else
  echo "SKIP  mount-ns scenarios (hosts/resolv/captive/proxy) — no mount-namespace support"
  SKIP=$((SKIP+1))
fi

# --------------------------------------------- v1-partial closers (§4.1 gaps)

# L7: live DoH bypass — a held-open connection to 1.1.1.1:443 while the OS
# resolver is elsewhere. The peer end impersonates the DoH provider.
mkveth 192.168.50.5 24 192.168.50.1 "" 192.168.50.1
cat >> /tmp/netdiag_veth.py <<'PY'
ipr.addr('add', index=i1, address='1.1.1.1', prefixlen=32)
PY
cat > /tmp/netdiag_doh.py <<'PY'
import socket, subprocess, sys, threading, time
srv = socket.socket(); srv.bind(('1.1.1.1', 443)); srv.listen(1)
threading.Thread(target=lambda: [srv.accept() for _ in iter(int, 1)], daemon=True).start()
time.sleep(0.2)
held = socket.create_connection(('1.1.1.1', 443))  # stays ESTABLISHED
rc = subprocess.call(sys.argv[1:])
held.close()
sys.exit(rc)
PY
expect doh_bypass_active $NS sh -c \
  "python3 /tmp/netdiag_veth.py && python3 /tmp/netdiag_doh.py $BIN"

# L7: Firefox TRR enabled — a fake profile in a fake HOME.
mkdir -p /tmp/ndhome/.mozilla/firefox/x9.default
printf 'user_pref("network.trr.mode", 2);\n' > /tmp/ndhome/.mozilla/firefox/x9.default/prefs.js
expect browser_doh_enabled $NS sh -c "HOME=/tmp/ndhome $BIN"

if $NSM true 2>/dev/null; then
  # L7: resolver answers without the AD flag → not validating (the fake
  # resolver from the disagreement scenario never sets AD).
  expect dnssec_not_validating $NSM sh -c \
    "mount --bind /tmp/netdiag_resolv /etc/resolv.conf && python3 /tmp/netdiag_lo.py && python3 /tmp/netdiag_dns.py $BIN"

  # L7: WPAD resolves (fake resolver answers everything) but the PAC
  # behind it is unreachable → pac_unusable.
  expect pac_unusable $NSM sh -c \
    "mount --bind /tmp/netdiag_resolv /etc/resolv.conf && python3 /tmp/netdiag_lo.py && python3 /tmp/netdiag_dns.py $BIN"

  # L7: TLS-inspection root CA in the trust store (bind-mounted bundle).
  printf 'Zscaler Root CA fake bundle entry\n' > /tmp/netdiag_ca
  expect tls_inspection_ca $NSM sh -c \
    "mount --bind /tmp/netdiag_ca /etc/ssl/certs/ca-certificates.crt && $BIN"
fi

# L4: firewall drops what a service listens on — needs nft inside the ns
# (root in the userns owns its own tables).
if command -v nft >/dev/null 2>&1 && $NS nft add table inet t 2>/dev/null; then
  cat > /tmp/netdiag_fw.py <<'PY'
import socket, subprocess, sys, threading
s = socket.socket(); s.bind(('0.0.0.0', 8080)); s.listen(1)
threading.Thread(target=lambda: [s.accept() for _ in iter(int, 1)], daemon=True).start()
sys.exit(subprocess.call(sys.argv[1:]))
PY
  mkveth 192.168.50.5 24
  expect firewall_blocking_listeners $NS sh -c \
    "python3 /tmp/netdiag_veth.py && \
     nft add table inet filter && \
     nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }' && \
     python3 /tmp/netdiag_fw.py $BIN"
else
  echo "SKIP  firewall_blocking_listeners — nft not usable in this environment"
  SKIP=$((SKIP+1))
fi

# -------------------------------------------- v1.2: the diff engine (§5.2/§7.1)
# Two namespaces play "the working machine" and "the broken one"; compare
# must produce the interpreted, ranked delta.
mkveth 192.168.50.5 24 192.168.50.1 "" 192.168.50.1
$NS sh -c "python3 /tmp/netdiag_veth.py && $BIN -save /tmp/netdiag_cmp_good.json" >/dev/null 2>&1 || true
mkveth 192.168.50.5 24 192.168.50.1 1280
$NS sh -c "python3 /tmp/netdiag_veth.py && $BIN -save /tmp/netdiag_cmp_bad.json" >/dev/null 2>&1 || true
if [ -s /tmp/netdiag_cmp_good.json ] && [ -s /tmp/netdiag_cmp_bad.json ]; then
  expect_text compare_ranked_delta "Start with #1" \
    "$BIN" compare /tmp/netdiag_cmp_good.json /tmp/netdiag_cmp_bad.json
  expect_text compare_mtu_drift "path MTU changed" \
    "$BIN" compare /tmp/netdiag_cmp_good.json /tmp/netdiag_cmp_bad.json
fi

# --------------------------------------------------------------- watch (§9)
# The time-domain verb, exercised end to end in a namespace: a short bounded
# run over a link that is down must (a) finish on its own, (b) name the fault
# as a STANDING one rather than claiming it caught an intermittent, and (c)
# still admit what it could not measure. The event-detection logic itself is
# unit-tested (internal/watch); this proves the verb wires up and terminates.
expect_text watch_terminates "watch summary" \
  $NS sh -c "$BIN watch -duration 8s -interval 3s"
expect_text watch_standing_fault "standing fault" \
  $NS sh -c "$BIN watch -duration 8s -interval 3s"
expect_text watch_admits_unmeasured "NOT green" \
  $NS sh -c "$BIN watch -duration 8s -interval 3s"

# A namespace whose gateway never answers: watch must catch it as a LOSS
# episode and blame the local side, not the internet. (The "clean window is
# not proof of health" path has no fault to inject by definition — it is
# unit-tested in internal/watch instead.)
mkveth 192.168.50.5 24 192.168.50.1
expect_text watch_catches_loss "loss to the gateway" \
  $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN watch -duration 8s -interval 3s"
expect_text watch_blames_local "at or before your own router" \
  $NS sh -c "python3 /tmp/netdiag_veth.py && $BIN watch -duration 8s -interval 3s"

# ------------------------------------------------------------------- netem tier
# Loss/latency shaping needs a kernel where sch_netem actually shapes.
# The check is functional, not syntactic: some sandboxed netstacks accept the
# qdisc and then route around it ("absence is never health" applies to test
# infrastructure too) — so netem must demonstrably kill an otherwise-alive
# gateway before the tier counts.
netem_works=0
if command -v tc >/dev/null 2>&1; then
  mkveth 192.168.50.5 24 192.168.50.1 "" 192.168.50.1
  if $NS sh -c "python3 /tmp/netdiag_veth.py && tc qdisc add dev veth0 root netem loss 100% && $BIN" 2>/dev/null \
      | grep -q "rule: gateway_unreachable"; then
    netem_works=1
  fi
fi
if [ "$netem_works" = 1 ]; then
  # Peer plays gateway AND the public anchor: 1.1.1.1/32 on veth1 makes the
  # upstream probes complete through the shaped link.
  mkanchor() {
    mkveth 192.168.50.5 24 192.168.50.1 "" 192.168.50.1
    cat >> /tmp/netdiag_veth.py <<'PY'
ipr.addr('add', index=i1, address='1.1.1.1', prefixlen=32)
PY
  }

  # L3: lossy gateway — peer answers but netem drops ~40% on the way out
  mkanchor
  expect gateway_lossy $NS sh -c \
    "python3 /tmp/netdiag_veth.py && tc qdisc add dev veth0 root netem loss 40% && $BIN"

  # L3: unstable latency — netem jitter on the egress path
  mkanchor
  expect high_jitter $NS sh -c \
    "python3 /tmp/netdiag_veth.py && tc qdisc add dev veth0 root netem delay 80ms 60ms && $BIN"

  # L3: clean LAN, lossy WAN — netem behind a u32 filter so only the
  # anchor-bound traffic is dropped; the gateway path stays clean.
  mkanchor
  expect upstream_lossy $NS sh -c \
    "python3 /tmp/netdiag_veth.py && \
     tc qdisc add dev veth0 root handle 1: prio && \
     tc qdisc add dev veth0 parent 1:3 netem loss 40% && \
     tc filter add dev veth0 protocol ip parent 1: u32 match ip dst 1.1.1.1/32 flowid 1:3 && \
     $BIN"

  # L7: slow DNS — the fake resolver answers, netem delays it past 500 ms
  expect dns_slow $NSM sh -c \
    "mount --bind /tmp/netdiag_resolv /etc/resolv.conf && python3 /tmp/netdiag_lo.py && \
     tc qdisc add dev lo root netem delay 600ms && \
     python3 /tmp/netdiag_dns.py $BIN"

  # L4: retransmission ratio — a TCP transfer across a 20%-lossy veth pumps
  # the namespace's own /proc/net/snmp counters (they are per-netns).
  cat > /tmp/netdiag_xfer.py <<'PY'
import socket, subprocess, sys, threading
def server():
    s = socket.socket(); s.bind(('192.168.50.1', 9)); s.listen(1)
    c, _ = s.accept()
    while c.recv(65536): pass
threading.Thread(target=server, daemon=True).start()
import time; time.sleep(0.3)
c = socket.create_connection(('192.168.50.1', 9), timeout=10)
c.settimeout(10)
blob = b'x' * 65536
try:
    for _ in range(40): c.sendall(blob)
except OSError: pass
c.close()
sys.exit(subprocess.call(sys.argv[1:]))
PY
  mkanchor
  expect high_retransmit_ratio $NS sh -c \
    "python3 /tmp/netdiag_veth.py && tc qdisc add dev veth0 root netem loss 20% && python3 /tmp/netdiag_xfer.py $BIN"
else
  echo "SKIP  netem scenarios (gateway_lossy/upstream_lossy/high_jitter/dns_slow/high_retransmit_ratio) — sch_netem absent or not actually shaping in this kernel"
  SKIP=$((SKIP+1))
fi

echo "----"
echo "$PASS scenarios pass, $SKIP tier(s) skipped honestly"
