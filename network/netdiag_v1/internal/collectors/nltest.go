package collectors

// Parsing nltest replies. Deliberately NOT in the _windows file: the logic is
// pure string handling, and keeping it cross-platform is what lets the
// captured field output (including a French DC's) be unit-tested anywhere.

import (
	"strconv"
	"strings"
)

// nltestStatuses pulls every "Status = <decimal> 0x<hex>" code out of an
// nltest reply. The labels around them are localized; the numbers are not.
// Any non-zero code means the verification failed, whatever nltest's exit
// code claims.
func nltestStatuses(out string) []int64 {
	var codes []int64
	for _, line := range strings.Split(out, "\n") {
		i := strings.LastIndex(line, "Status")
		if i < 0 {
			continue
		}
		rest := line[i:]
		eq := strings.Index(rest, "=")
		if eq < 0 {
			continue
		}
		fields := strings.Fields(rest[eq+1:])
		if len(fields) == 0 {
			continue
		}
		if code, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			codes = append(codes, code)
		}
	}
	return codes
}
