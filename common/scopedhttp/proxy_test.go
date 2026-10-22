package scopedhttp

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestProductionProxyDNSAndProviderSharePinnedOutbound(t *testing.T) {
	for _, kind := range []string{"http", "socks"} {
		t.Run(kind, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			seen := make(chan string, 8)
			failures := make(chan error, 8)
			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(2 * time.Second))
						reader := bufio.NewReader(conn)
						var target string
						if kind == "http" {
							r, err := http.ReadRequest(reader)
							if err != nil {
								failures <- err
								return
							}
							if r.Method != "CONNECT" {
								failures <- fmt.Errorf("non-CONNECT proxy request")
								return
							}
							target = r.Host
							io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
						} else {
							var greeting [2]byte
							if _, err = io.ReadFull(reader, greeting[:]); err != nil {
								failures <- err
								return
							}
							methods := make([]byte, greeting[1])
							io.ReadFull(reader, methods)
							conn.Write([]byte{5, 0})
							var request [4]byte
							if _, err = io.ReadFull(reader, request[:]); err != nil {
								failures <- err
								return
							}
							if request[0] != 5 || request[1] != 1 {
								failures <- fmt.Errorf("unexpected SOCKS command")
								return
							}
							n := 4
							if request[3] == 4 {
								n = 16
							} else if request[3] != 1 {
								failures <- fmt.Errorf("proxy got DNS/domain target type %d", request[3])
								return
							}
							address := make([]byte, n+2)
							if _, err = io.ReadFull(reader, address); err != nil {
								failures <- err
								return
							}
							target = net.JoinHostPort(net.IP(address[:n]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(address[n:]))))
							conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
						}
						seen <- target
						if target == "192.0.2.53:53" {
							var hdr [2]byte
							if _, err = io.ReadFull(reader, hdr[:]); err != nil {
								failures <- err
								return
							}
							wire := make([]byte, binary.BigEndian.Uint16(hdr[:]))
							if _, err = io.ReadFull(reader, wire); err != nil {
								failures <- err
								return
							}
							q := new(dns.Msg)
							if err = q.Unpack(wire); err != nil {
								failures <- err
								return
							}
							if q.Question[0].Name != "ip-api.com." {
								failures <- fmt.Errorf("unexpected DNS question %s", q.Question[0].Name)
								return
							}
							r := new(dns.Msg)
							r.SetReply(q)
							rr, _ := dns.NewRR("ip-api.com. 30 IN A 203.0.113.18")
							r.Answer = []dns.RR{rr}
							out, _ := r.Pack()
							binary.BigEndian.PutUint16(hdr[:], uint16(len(out)))
							conn.Write(hdr[:])
							conn.Write(out)
						} else if target == "203.0.113.18:80" {
							r, err := http.ReadRequest(reader)
							if err != nil {
								failures <- err
								return
							}
							if r.Host != "ip-api.com" || r.URL.RequestURI() != strings.TrimPrefix(ipAPIURL, "http://ip-api.com") {
								failures <- fmt.Errorf("unexpected provider URL")
								return
							}
							body := `{"status":"success","query":"203.0.113.77","country":"test"}`
							fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
						} else {
							failures <- fmt.Errorf("unpinned proxy destination %s", target)
						}
					}()
				}
			}()
			_, portText, _ := net.SplitHostPort(listener.Addr().String())
			snapshot := fmt.Sprintf(`{"outbounds":[{"type":%q,"tag":"leaf","server":"127.0.0.1","server_port":%s}],"dns":{"final":"d","servers":[{"type":"tcp","tag":"d","server":"192.0.2.53","detour":"leaf"}]}}`, kind, portText)
			plan, err := NewPlan([]byte(snapshot), []string{"leaf"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			session, err := NewSession(ctx, context.Background(), plan)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if _, err = session.Lookup("ipApi"); err != nil {
				select {
				case failure := <-failures:
					t.Fatal(failure)
				default:
					t.Fatal(err)
				}
			}
			first, second := <-seen, <-seen
			if first != "192.0.2.53:53" || second != "203.0.113.18:80" {
				t.Fatalf("different route: %s %s", first, second)
			}
			select {
			case err := <-failures:
				t.Fatal(err)
			default:
			}
		})
	}
}
