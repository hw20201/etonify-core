package scopedhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

const ipAPIURL = "http://ip-api.com/json/?fields=status,message,query,country,countryCode,regionName,city,isp,org,as"

// No caller-controlled URL enters the transport. In particular the only
// plaintext exception is this exact free ip-api endpoint and minimal field list.
func providerURLAllowed(raw string) bool {
	if raw == ipAPIURL || raw == "https://ipwho.is/" || raw == "https://api.ipquery.io/" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "api.ipquery.io" || u.User != nil || u.Fragment != "" || u.RawQuery != "format=json" {
		return false
	}
	_, err = netip.ParseAddr(strings.TrimPrefix(u.Path, "/"))
	return err == nil && strings.HasPrefix(u.Path, "/") && !strings.Contains(strings.TrimPrefix(u.Path, "/"), "/")
}
func (s *Session) fetch(raw, accept string) ([]byte, error) {
	if !providerURLAllowed(raw) {
		return nil, errors.New("scoped provider URL rejected")
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(s.ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("Cache-Control", "no-cache")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, errors.New("scoped provider redirect rejected")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scoped provider HTTP %d", response.StatusCode)
	}
	if response.ContentLength > bodyLimit {
		return nil, errors.New("scoped provider body exceeds 16KiB")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, bodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > bodyLimit {
		return nil, errors.New("scoped provider body exceeds 16KiB")
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	return body, nil
}
func (s *Session) Lookup(provider string) ([]byte, error) {
	var raw string
	var expected netip.Addr
	switch provider {
	case "ipQuery":
		plain, err := s.fetch("https://api.ipquery.io/", "text/plain")
		if err != nil {
			return nil, err
		}
		expected, err = netip.ParseAddr(strings.TrimSpace(string(plain)))
		if err != nil || expected.Zone() != "" {
			return nil, errors.New("invalid ipquery first-stage IP")
		}
		expected = expected.Unmap()
		u := url.URL{Scheme: "https", Host: "api.ipquery.io", Path: "/" + expected.String(), RawQuery: "format=json"}
		raw = u.String()
	case "ipApi":
		raw = ipAPIURL
	case "ipWho":
		raw = "https://ipwho.is/"
	default:
		return nil, errors.New("unknown scoped provider")
	}
	body, err := s.fetch(raw, "application/json")
	if err != nil {
		return nil, err
	}
	var data struct {
		IP      string `json:"ip"`
		Query   string `json:"query"`
		Status  string `json:"status"`
		Success *bool  `json:"success"`
	}
	if err = json.Unmarshal(body, &data); err != nil {
		return nil, errors.New("invalid scoped provider JSON")
	}
	address := data.IP
	if provider == "ipApi" {
		if data.Status != "success" {
			return nil, errors.New("ip-api query failed")
		}
		address = data.Query
	}
	if provider == "ipWho" && data.Success != nil && !*data.Success {
		return nil, errors.New("ipwho query failed")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || ip.Zone() != "" {
		return nil, errors.New("invalid scoped provider IP")
	}
	if expected.IsValid() && expected != ip.Unmap() {
		return nil, errors.New("ipquery second-stage IP mismatch")
	}
	return body, nil
}
