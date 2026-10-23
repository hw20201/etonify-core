package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/stretchr/testify/require"
)

// The application emits logical AND [block, NOT allow] for both route and DNS.
// An exception must exempt rejection, not terminate the remaining routing policy.
func TestRouteAdBlockAllowDoesNotTerminateChinaRouting(t *testing.T) {
	t.Parallel()
	chinaSet := newLocalRuleSetForTest("cn-geosite-cn", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
		addDestinationAddressItem(t, rule, []string{"allowed.cn", "blocked.cn"}, nil)
	}))
	blockSet := newLocalRuleSetForTest("adblock-block", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
		// A real intersection: allowed.cn belongs to BOTH lists.
		addDestinationAddressItem(t, rule, []string{"blocked.cn", "allowed.cn"}, []string{"blocked.example"})
	}))
	allowSet := newLocalRuleSetForTest("adblock-allow", headlessDefaultRule(t, func(rule *abstractDefaultRule) {
		addDestinationAddressItem(t, rule, []string{"allowed.cn", "allowed.example"}, nil)
	}))
	newRejectTerms := func(dns bool) []adapter.HeadlessRule {
		buildBlock := func(rule *abstractDefaultRule) {
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{blockSet}})
		}
		buildNotAllow := func(rule *abstractDefaultRule) {
			rule.invert = true
			addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{allowSet}})
		}
		if dns {
			return []adapter.HeadlessRule{dnsRuleForTest(buildBlock), dnsRuleForTest(buildNotAllow)}
		}
		return []adapter.HeadlessRule{routeRuleForTest(buildBlock), routeRuleForTest(buildNotAllow)}
	}
	rejectRoute := &LogicalRule{abstractLogicalRule: abstractLogicalRule{
		mode: C.LogicalTypeAnd, rules: newRejectTerms(false),
	}}
	rejectDNS := &LogicalDNSRule{abstractLogicalRule: abstractLogicalRule{
		mode: C.LogicalTypeAnd, rules: newRejectTerms(true),
	}}
	buildChina := func(rule *abstractDefaultRule) {
		addRuleSetItem(rule, &RuleSetItem{setList: []adapter.RuleSet{chinaSet}})
	}
	chinaRoute := routeRuleForTest(buildChina)
	chinaDNS := dnsRuleForTest(buildChina)

	for _, tc := range []struct {
		name, domain  string
		reject, china bool
	}{
		{"allow and block intersection in China", "allowed.cn", false, true},
		{"block without allow in China", "blocked.cn", true, true},
		{"block without allow outside China", "blocked.example", true, false},
		{"allow outside China retains proxy", "allowed.example", false, false},
		{"ordinary non-China retains proxy", "ordinary.example", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, matcher := range []struct {
				name          string
				reject, china adapter.HeadlessRule
			}{{"route", rejectRoute, chinaRoute}, {"DNS", rejectDNS, chinaDNS}} {
				t.Run(matcher.name, func(t *testing.T) {
					metadata := testMetadata(tc.domain)
					rejected := matcher.reject.Match(&metadata)
					require.Equal(t, tc.reject, rejected, "block AND NOT allow")
					metadata.ResetRuleCache()
					china := matcher.china.Match(&metadata)
					require.Equal(t, tc.china, china, "independent China match")
					// Model first-match policy without creating outbound sockets or
					// DNS servers: reject, otherwise China direct, otherwise proxy.
					decision := "proxy"
					if rejected {
						decision = "reject"
					} else if china {
						decision = "direct"
					}
					want := "proxy"
					if tc.reject {
						want = "reject"
					} else if tc.china {
						want = "direct"
					}
					require.Equal(t, want, decision)
				})
			}
		})
	}
}
