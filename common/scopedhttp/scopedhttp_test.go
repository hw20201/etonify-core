package scopedhttp

import "testing"

const validSnapshot = `{"outbounds":[{"type":"http","tag":"leaf","server":"192.0.2.10","server_port":8080}],"dns":{"final":"d","servers":[{"type":"tcp","tag":"d","server":"192.0.2.53","server_port":53,"detour":"leaf"}]}}`

func TestPlanSnapshotIsIndependent(t *testing.T) {
	b := []byte(validSnapshot)
	p, e := NewPlan(b, []string{"leaf"})
	if e != nil {
		t.Fatal(e)
	}
	id := p.ID()
	b[0] = ' '
	if p.ID() != id || id == "" {
		t.Fatal("plan changed with caller snapshot mutation")
	}
}
func TestPlanRejectsUnknownChainAndProxyHostname(t *testing.T) {
	if _, e := NewPlan([]byte(validSnapshot), []string{"not-in-snapshot"}); e == nil {
		t.Fatal("unknown chain accepted")
	}
	s := []byte(`{"outbounds":[{"type":"http","tag":"leaf","server":"proxy.example","server_port":8080}],"dns":{"final":"d","servers":[{"type":"tcp","tag":"d","server":"192.0.2.53","server_port":53,"detour":"leaf"}]}}`)
	if _, e := NewPlan(s, []string{"leaf"}); e == nil {
		t.Fatal("hostname proxy accepted")
	}
}
func TestPlanRejectsDNSWrongDetour(t *testing.T) {
	s := []byte(`{"outbounds":[{"type":"http","tag":"leaf","server":"192.0.2.10","server_port":8080}],"dns":{"final":"d","servers":[{"type":"tcp","tag":"d","server":"192.0.2.53","server_port":53,"detour":"elsewhere"}]}}`)
	if _, e := NewPlan(s, []string{"leaf"}); e == nil {
		t.Fatal("wrong DNS detour accepted")
	}
}
