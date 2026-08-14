package ref

import (
	"strings"
	"testing"
)

// Bug #33: the ports table was read as "my open ports". Every lookup must say
// what it is before it says anything else.
func TestEveryLookupStatesItIsNotAScan(t *testing.T) {
	for _, args := range [][]string{nil, {"port"}, {"port", "3389"}, {"subnet"}, {"nonsense"}} {
		out := Lookup(args)
		if !strings.Contains(out, "REFERENCE ONLY") || !strings.Contains(out, "NOT a scan") {
			t.Errorf("Lookup(%v) does not say it is a reference:\n%.200s", args, out)
		}
		if strings.Index(out, "REFERENCE ONLY") > 10 {
			t.Errorf("Lookup(%v): the disclaimer is not the FIRST thing on screen", args)
		}
	}
}
