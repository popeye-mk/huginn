package interpret

import "testing"

// Fixture-style tests (spec §18 v0/v1): facts in, expected rule IDs out.
func TestSeedRulesAgainstFixtures(t *testing.T) {
	rules, _, err := LoadRules("")
	if err != nil {
		t.Fatalf("embedded KB failed to load: %v", err)
	}

	cases := []struct {
		name  string
		facts map[string]any
		want  map[string]bool // rule IDs expected to fire
	}{
		{
			name: "healthy network fires nothing",
			facts: map[string]any{
				"link_up": true, "link_duplex": "full", "apipa_only": false,
				"default_route_present": true, "has_ipv4_global": true,
				"gateway_reachable": true, "gateway_loss_pct": 0,
				"dns_resolution_ok": true, "dns_servers_count": 2,
			},
			want: map[string]bool{},
		},
		{
			name:  "half duplex fires L1",
			facts: map[string]any{"link_duplex": "half"},
			want:  map[string]bool{"duplex_mismatch": true},
		},
		{
			name:  "APIPA-only fires no-DHCP",
			facts: map[string]any{"apipa_only": true},
			want:  map[string]bool{"apipa_no_dhcp": true},
		},
		{
			name: "DNS dead fires L7, with or without a gateway verdict",
			facts: map[string]any{
				"dns_resolution_ok": false, "dns_servers_count": 1,
			},
			want: map[string]bool{"dns_resolution_failure": true},
		},
		{
			name:  "everything down fires the L1 headline",
			facts: map[string]any{"link_up": false},
			want:  map[string]bool{"link_down": true},
		},
		{
			name:  "lossy gateway crosses threshold",
			facts: map[string]any{"gateway_reachable": true, "gateway_loss_pct": 33},
			want:  map[string]bool{"gateway_lossy": true},
		},
		{
			name:  "unmeasured facts never fire rules (absence is never health)",
			facts: map[string]any{},
			want:  map[string]bool{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]bool{}
			for _, f := range Evaluate(rules, tc.facts) {
				got[f.ID] = true
			}
			for id := range tc.want {
				if !got[id] {
					t.Errorf("expected rule %q to fire, it did not", id)
				}
			}
			for id := range got {
				if !tc.want[id] {
					t.Errorf("rule %q fired unexpectedly", id)
				}
			}
		})
	}
}
