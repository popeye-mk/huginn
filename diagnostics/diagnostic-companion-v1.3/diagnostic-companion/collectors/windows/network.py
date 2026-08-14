"""Windows network collector (spec §4.1) — IP config, gateway, DNS,
DNS resolution test, ping to gateway and a public target.

Unverified against a real Windows box — see collectors/windows/_powershell.py.
Highest-risk of the four Windows collectors: it chains five cmdlets
(Get-NetIPConfiguration, Get-DnsClientServerAddress, Resolve-DnsName,
Test-Connection x2) into one script, and PowerShell's ConvertTo-Json
collapses single-item arrays/hashtables in ways that are easy to get
subtly wrong without a machine to check against. Treat this one as the
first candidate for real-hardware testing.
"""

import json

from collectors.windows._powershell import run_powershell

PS_COMMAND = r"""
$ip = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
$gateway = $ip.IPv4DefaultGateway.NextHop
$dns = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | Select-Object -First 1).ServerAddresses
$dnsTest = @{}
foreach ($d in @('example.com','cloudflare.com','wikipedia.org')) {
  try { Resolve-DnsName $d -ErrorAction Stop | Out-Null; $dnsTest[$d] = $true } catch { $dnsTest[$d] = $false }
}
$gwPing = $false
if ($gateway) { $gwPing = Test-Connection -ComputerName $gateway -Count 1 -Quiet }
$pubPing = Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet
[PSCustomObject]@{
  Interface = $ip.InterfaceAlias
  Gateway = $gateway
  DnsServers = $dns
  DnsResults = $dnsTest
  GatewayReachable = $gwPing
  PublicReachable = $pubPing
} | ConvertTo-Json -Compress -Depth 4
""".strip()


# PowerShell subprocess timeout. Must stay BELOW this collector's outer
# timeout in cli.py: the outer wrapper is a thread, and a thread timeout
# cannot kill a running subprocess. If the outer fires first, the query
# is abandoned rather than terminated and keeps running in the
# background. Enforced by tests/test_timeouts.py.
PS_TIMEOUT_S = 20


def parse(raw_json):
    obj = json.loads(raw_json)

    dns_servers = obj.get("DnsServers") or []
    if isinstance(dns_servers, str):
        dns_servers = [dns_servers]

    dns_results = obj.get("DnsResults") or {}
    gateway = obj.get("Gateway")

    return {
        "interface": obj.get("Interface"),
        "gateway": gateway,
        "dns_servers": dns_servers,
        "dns_resolution": dns_results,
        "dns_any_failed": any(not ok for ok in dns_results.values()) if dns_results else None,
        "gateway_ping": {"target": gateway, "reachable": obj.get("GatewayReachable")},
        "public_ping": {"target": "1.1.1.1", "reachable": obj.get("PublicReachable")},
    }


def collect():
    raw = run_powershell(PS_COMMAND, timeout_s=PS_TIMEOUT_S)
    return parse(raw)
