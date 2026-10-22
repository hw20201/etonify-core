package scopedhttp

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	M "github.com/sagernet/sing/common/metadata"
)

func providerTestSession(t *testing.T, timeout time.Duration, handler http.HandlerFunc, dnsDelay time.Duration) (*Session, context.CancelFunc) {
	t.Helper()
	secure := httptest.NewTLSServer(handler)
	t.Cleanup(secure.Close)
	plain := httptest.NewServer(handler)
	t.Cleanup(plain.Close)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	plan, err := NewPlan([]byte(validSnapshot), []string{"leaf"})
	if err != nil {
		t.Fatal(err)
	}
	s := newSession(ctx, context.Background(), plan)
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(secure.Certificate())
	s.transport.TLSClientConfig.RootCAs = roots
	// Certificate verification is real: httptest's cert has example.com but our
	// production request retains api.ipquery.io. Supply a test-only SNI matching
	// the trusted fixture; production never overrides provider SNI.
	s.transport.TLSClientConfig.ServerName = "example.com"
	s.proxyDial = func(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
		if target.IsDomain() {
			t.Errorf("provider name leaked to proxy: %s", target)
			return nil, fmt.Errorf("domain target")
		}
		if target.Port == 53 {
			client, peer := net.Pipe()
			go func() {
				defer peer.Close()
				var hdr [2]byte
				if _, err := io.ReadFull(peer, hdr[:]); err != nil {
					return
				}
				wire := make([]byte, binary.BigEndian.Uint16(hdr[:]))
				if _, err := io.ReadFull(peer, wire); err != nil {
					return
				}
				q := new(dns.Msg)
				if q.Unpack(wire) != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(dnsDelay):
				}
				r := new(dns.Msg)
				r.SetReply(q)
				rr, _ := dns.NewRR(q.Question[0].Name + " 30 IN A 203.0.113.10")
				r.Answer = []dns.RR{rr}
				out, _ := r.Pack()
				binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
				peer.Write(hdr[:])
				peer.Write(out)
			}()
			return client, nil
		}
		address := strings.TrimPrefix(secure.URL, "https://")
		if target.Port == 80 {
			address = strings.TrimPrefix(plain.URL, "http://")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return s, cancel
}

func TestPublicIPTwoStageSameProviderAndIP(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint(mismatch), func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			s, _ := providerTestSession(t, time.Second, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.Host+r.URL.RequestURI())
				mu.Unlock()
				if r.URL.Path == "/" {
					fmt.Fprint(w, "203.0.113.9\n")
					return
				}
				ip := "203.0.113.9"
				if mismatch {
					ip = "203.0.113.8"
				}
				fmt.Fprintf(w, `{"ip":%q,"location":{"city":"same-provider"}}`, ip)
			}, 0)
			body, err := s.Lookup("ipQuery")
			if mismatch && err == nil {
				t.Fatal("different second-stage IP accepted")
			}
			if !mismatch && (err != nil || !strings.Contains(string(body), "same-provider")) {
				t.Fatalf("body=%s err=%v", body, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(paths) != 2 || paths[0] != "api.ipquery.io/" || paths[1] != "api.ipquery.io/203.0.113.9?format=json" {
				t.Fatalf("provider changed: %v", paths)
			}
		})
	}
}
func TestPublicIPRedirectRejectedWithoutFollowing(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	s, _ := providerTestSession(t, time.Second, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Location", "https://evil.invalid/changed")
		w.WriteHeader(302)
	}, 0)
	if _, err := s.Lookup("ipWho"); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect accepted: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("redirect followed %d times", calls)
	}
}
func TestPublicIPBodySizeAndProviderIsolation(t *testing.T) {
	for _, provider := range []string{"ipApi", "ipWho"} {
		t.Run(provider, func(t *testing.T) {
			s, _ := providerTestSession(t, time.Second, func(w http.ResponseWriter, r *http.Request) {
				if provider == "ipApi" {
					if r.Host != "ip-api.com" || r.URL.RequestURI() != strings.TrimPrefix(ipAPIURL, "http://ip-api.com") {
						t.Errorf("unapproved plaintext endpoint %s %s", r.Host, r.URL)
					}
				} else if r.Host != "ipwho.is" {
					t.Errorf("provider mixed: %s", r.Host)
				}
				fmt.Fprint(w, strings.Repeat("x", bodyLimit+1))
			}, 0)
			if _, err := s.Lookup(provider); err == nil || !strings.Contains(err.Error(), "16KiB") {
				t.Fatalf("large body accepted: %v", err)
			}
		})
	}
}
func TestPublicIPWholeDeadlineAcrossDNSAndBothCalls(t *testing.T) {
	s, _ := providerTestSession(t, 200*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			time.Sleep(65 * time.Millisecond)
			fmt.Fprint(w, "203.0.113.9")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ip":"203.0.113.9","unused":"`)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(400 * time.Millisecond):
			fmt.Fprint(w, `"}`)
		}
	}, 65*time.Millisecond)
	start := time.Now()
	if _, err := s.Lookup("ipQuery"); err == nil {
		t.Fatal("deadline renewed between stages")
	}
	if time.Since(start) > 600*time.Millisecond {
		t.Fatal("whole-query deadline did not bound body")
	}
}
func TestPublicIPCancelClosesOnlyItsSessionSockets(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	s, cancel := providerTestSession(t, 2*time.Second, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(stopped)
	}, 0)
	done := make(chan error, 1)
	go func() { _, err := s.Lookup("ipWho"); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not enter body")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not close socket")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("server socket survived cancellation")
	}
	other, _ := providerTestSession(t, time.Second, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"ip":"203.0.113.17","success":true}`) }, 0)
	if _, err := other.Lookup("ipWho"); err != nil {
		t.Fatalf("independent session closed: %v", err)
	}
}
