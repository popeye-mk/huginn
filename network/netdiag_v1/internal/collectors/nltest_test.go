package collectors

import "testing"

// Captured verbatim from a Win 11 member whose computer-account password had
// just been reset on the DC. nltest reports the failure in its BODY and then
// exits zero — so a check that judges by exit code (or by /sc_query, which
// answers from the live session) prints a confident, wrong "trust intact".
const scVerifyBroken = `Flags: 800000b0 HAS_IP  HAS_TIMESERV  Authentication Service: Kerberos
Trusted DC Name \\server.corp.local
Trusted DC Connection Status Status = 0 0x0 NERR_Success
Trust Verification Status = 86 0x56 ERROR_INVALID_PASSWORD
The command completed successfully`

const scVerifyOK = `Flags: 30 HAS_IP  HAS_TIMESERV  Authentication Service: Kerberos
Trusted DC Name \\server.corp.local
Trusted DC Connection Status Status = 0 0x0 NERR_Success
Trust Verification Status = 0 0x0 NERR_Success
The command completed successfully`

// A French DC's reply: the labels translate, the numbers do not.
const scVerifyLocalized = `Indicateurs : 30 HAS_IP  HAS_TIMESERV
Nom du contrôleur de domaine approuvé \\server.corp.local
État de la connexion Status = 0 0x0 NERR_Success
État de la vérification d'approbation Status = 86 0x56 ERROR_INVALID_PASSWORD
La commande a été correctement exécutée`

func TestNltestStatusesReadsTheBodyNotTheExitCode(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		want    []int64
		healthy bool
	}{
		{"broken", scVerifyBroken, []int64{0, 86}, false},
		{"ok", scVerifyOK, []int64{0, 0}, true},
		{"localized", scVerifyLocalized, []int64{0, 86}, false},
	}
	for _, c := range cases {
		got := nltestStatuses(c.out)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		healthy := true
		for i, code := range got {
			if code != c.want[i] {
				t.Errorf("%s: status %d = %d, want %d", c.name, i, code, c.want[i])
			}
			if code != 0 {
				healthy = false
			}
		}
		if healthy != c.healthy {
			t.Errorf("%s: healthy=%v, want %v", c.name, healthy, c.healthy)
		}
	}
}

// Unparsable output must yield NO codes, so the caller reports "could not be
// verified" rather than inventing a green.
func TestNltestStatusesRefusesToGuess(t *testing.T) {
	if got := nltestStatuses("nltest is not recognized"); len(got) != 0 {
		t.Errorf("invented statuses from garbage: %v", got)
	}
}
