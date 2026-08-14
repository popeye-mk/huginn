package collectors

// Hygiene analysis (§12): the security-posture reading of facts the tool
// already collects, plus a few cheap local reads. This is REPORTING, never
// exploitation — it names exposure and the fix, and does nothing offensive.
//
// The judgement lives here (cross-platform, unit-tested); the per-OS reads
// live in hygiene_linux.go / hygiene_windows.go.

import "fmt"

// riskyListener describes a port that is worth a second look when something
// on this machine is listening on it. "Worth checking" is the claim — never
// "you are compromised".
type riskyListener struct {
	Port int
	Name string
	Why  string
}

// The set is deliberately small and defensible: protocols that are either
// unauthenticated, plaintext, or the classic lateral-movement surface.
var riskyListeners = map[int]riskyListener{
	23:   {23, "Telnet", "credentials and everything else travel in clear text"},
	21:   {21, "FTP", "credentials in clear text unless FTPS is enforced"},
	69:   {69, "TFTP", "no authentication at all"},
	135:  {135, "MSRPC", "broad remote surface; should not face untrusted networks"},
	139:  {139, "NetBIOS session", "legacy SMB path, usually replaceable by 445 alone"},
	445:  {445, "SMB", "file sharing — fine on a LAN, never toward the internet"},
	1433: {1433, "MSSQL", "database exposed beyond the app tier is rarely intended"},
	3306: {3306, "MySQL", "database exposed beyond the app tier is rarely intended"},
	3389: {3389, "RDP", "the single most brute-forced port on the internet"},
	5432: {5432, "PostgreSQL", "database exposed beyond the app tier is rarely intended"},
	5900: {5900, "VNC", "often unauthenticated or weakly authenticated"},
	161:  {161, "SNMP", "v1/v2c community strings are effectively plaintext passwords"},
}

// hygieneFindings turns the collected facts into posture facts. Kept separate
// from the collectors so the same logic runs on both OSes and can be tested
// without a machine in a particular state.
func hygieneFacts(listening []int, poisoning map[string]bool, smb1, rdpNLA *bool) map[string]any {
	data := map[string]any{}

	// --- exposed services worth a look ---
	var names []string
	for _, p := range listening {
		if r, ok := riskyListeners[p]; ok {
			names = append(names, fmt.Sprintf("%d/%s", r.Port, r.Name))
		}
	}
	// An empty list is reported as a count of zero, not as a null: "nothing
	// risky is listening" is a measured result and should read like one.
	data["hygiene_risky_listener_count"] = len(names)
	if len(names) > 0 {
		data["hygiene_risky_listeners"] = names
	}

	// --- name-resolution poisoning surface (the Responder classic) ---
	var on []string
	for proto, enabled := range poisoning {
		if enabled {
			on = append(on, proto)
		}
	}
	if len(poisoning) > 0 {
		data["hygiene_poisoning_protocols"] = on
		data["hygiene_poisoning_exposed"] = len(on) > 0
	}

	if smb1 != nil {
		data["hygiene_smb1_enabled"] = *smb1
	}
	if rdpNLA != nil {
		data["hygiene_rdp_nla"] = *rdpNLA
	}
	return data
}
