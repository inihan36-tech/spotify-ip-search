package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var nonPublicRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

func publicIP(value string) string {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.As4()[0] >= 240 {
		return ""
	}
	for _, prefix := range nonPublicRanges {
		if prefix.Contains(address) {
			return ""
		}
	}
	return address.String()
}

type response struct {
	status   int
	headers  http.Header
	location *url.URL
	body     []byte
}

func dialer(interfaceIndex uint32, timeout time.Duration) net.Dialer {
	dial := net.Dialer{Timeout: min(timeout, 4*time.Second)}
	if interfaceIndex != 0 {
		dial.Control = func(_, _ string, raw syscall.RawConn) error {
			return bindInterface(raw, interfaceIndex)
		}
	}
	return dial
}

func request(rawURL, pinnedIP string, interfaceIndex uint32, timeout time.Duration, limit int64, accept string) (response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return response{}, err
	}
	if req.URL.Scheme != "https" {
		return response{}, errors.New("требуется HTTPS")
	}
	req.Header.Set("User-Agent", "SpotifyIpSearch/"+version)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	dial := dialer(interfaceIndex, timeout)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			if pinnedIP != "" {
				address = net.JoinHostPort(pinnedIP, "443")
			}
			return dial.DialContext(ctx, "tcp4", address)
		},
		TLSHandshakeTimeout: min(timeout, 4*time.Second),
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return response{}, err
	}
	if int64(len(data)) > limit {
		return response{}, errors.New("ответ слишком большой")
	}
	location, _ := res.Location()
	return response{res.StatusCode, res.Header, location, data}, nil
}

func redirected(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

func validSpotifyResponse(domain string, res response) bool {
	body := bytes.TrimSpace(res.body)
	switch domain {
	case "api.spotify.com":
		var reply struct {
			Error struct {
				Status  int
				Message string
			}
		}
		return res.status == 401 && json.Unmarshal(body, &reply) == nil && reply.Error.Status == 401 &&
			strings.Contains(strings.ToLower(reply.Error.Message), "access token")
	case "spclient.wg.spotify.com", "gew1-spclient.spotify.com", "api-partner.spotify.com":
		return res.status == 401 && strings.Contains(strings.ToLower(res.headers.Get("WWW-Authenticate")), `realm="spotify"`)
	case "i.scdn.co":
		return res.status == 200 && len(body) > 0 && strings.HasPrefix(strings.ToLower(res.headers.Get("Content-Type")), "image/")
	case "login5.spotify.com", "aet.spotify.com":
		return res.status == 404 && len(body) == 0
	case "gew1-dealer.spotify.com":
		return res.status == 401 && string(body) == "401 Unauthorized"
	case "encore.scdn.co", "accounts.scdn.co", "www-growth.scdn.co", "scdn.co", "www.scdn.co":
		text := strings.ToLower(string(body))
		return (res.status == 200 && len(body) > 0) || (res.status == 403 &&
			(strings.Contains(text, "access denied") || strings.Contains(text, "forbidden")))
	case "spotify.com", "www.spotify.com":
		if redirected(res.status) && res.location != nil {
			expected := "www.spotify.com"
			if domain == "www.spotify.com" {
				expected = "open.spotify.com"
			}
			return res.location.Scheme == "https" && strings.EqualFold(res.location.Host, expected)
		}
	}
	text := strings.ToLower(string(body))
	return res.status == 200 && strings.Contains(text, "<html") && strings.Contains(text, "spotify")
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

type pair struct{ ip, domain string }

type probeResult struct {
	pair
	ok       bool
	timedOut bool
	reason   string
	elapsed  time.Duration
}

func probe(candidate pair, interfaceIndex uint32, timeout time.Duration, retry bool) probeResult {
	address := "https://" + candidate.domain + config.Targets[candidate.domain]
	start := time.Now()
	for range 3 {
		res, err := request(address, candidate.ip, interfaceIndex, timeout, 4_000_000, "")
		if retry && isTimeout(err) {
			retry = false
			res, err = request(address, candidate.ip, interfaceIndex, timeout, 4_000_000, "")
		}
		if err != nil {
			return probeResult{pair: candidate, reason: err.Error(), timedOut: isTimeout(err)}
		}
		if redirected(res.status) && res.location != nil && res.location.Scheme == "https" &&
			res.location.User == nil && strings.EqualFold(res.location.Host, candidate.domain) {
			address = res.location.String()
			continue
		}
		return probeResult{pair: candidate, ok: validSpotifyResponse(candidate.domain, res),
			reason: fmt.Sprintf("HTTP %d", res.status), elapsed: time.Since(start)}
	}
	return probeResult{pair: candidate, reason: "слишком много перенаправлений"}
}

func smartDNS(domain string, interfaceIndex uint32) ([]string, error) {
	var lastErr error
	for _, server := range config.SmartDNS {
		addresses, err := queryTLS(domain, server, interfaceIndex)
		if err == nil && len(addresses) > 0 {
			return addresses, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func queryTLS(domain, server string, interfaceIndex uint32) ([]string, error) {
	const timeout = 4 * time.Second
	message := dnsQuery(domain, 0x5350)
	query, err := message.Pack()
	if err != nil {
		return nil, err
	}
	dial := dialer(interfaceIndex, timeout)
	connection, err := tls.DialWithDialer(&dial, "tcp4", net.JoinHostPort(server, "853"),
		&tls.Config{ServerName: "dns.malw.link"})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := connection.Write(append(frame, query...)); err != nil {
		return nil, err
	}
	var size uint16
	if err := binary.Read(connection, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	answer := make([]byte, size)
	if _, err := io.ReadFull(connection, answer); err != nil {
		return nil, err
	}
	return dnsReply(message, answer)
}

func dnsQuery(domain string, id uint16) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(domain + "."),
			Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
}

func dnsReply(message dnsmessage.Message, answer []byte) ([]string, error) {
	var reply dnsmessage.Message
	if err := reply.Unpack(answer); err != nil {
		return nil, err
	}
	if reply.ID != message.ID || !reply.Response || reply.Truncated || reply.RCode != dnsmessage.RCodeSuccess ||
		len(reply.Questions) != 1 || reply.Questions[0].Type != dnsmessage.TypeA || reply.Questions[0].Class != dnsmessage.ClassINET ||
		!strings.EqualFold(reply.Questions[0].Name.String(), message.Questions[0].Name.String()) {
		return nil, errors.New("неожиданный ответ DNS")
	}
	var addresses []string
	for _, record := range reply.Answers {
		if data, ok := record.Body.(*dnsmessage.AResource); ok {
			addresses = append(addresses, netip.AddrFrom4(data.A).String())
		}
	}
	return addresses, nil
}

func queryWireDoH(domain string, interfaceIndex uint32, endpoint [2]string) ([]string, error) {
	message := dnsQuery(domain, 0)
	query, err := message.Pack()
	if err != nil {
		return nil, err
	}
	res, err := request(endpoint[0]+"?dns="+base64.RawURLEncoding.EncodeToString(query), endpoint[1], interfaceIndex,
		3*time.Second, 64_000, "application/dns-message")
	if err != nil {
		return nil, err
	}
	if res.status != http.StatusOK {
		return nil, fmt.Errorf("DNS: HTTP %d", res.status)
	}
	return dnsReply(message, res.body)
}

func queryDoH(domain string, interfaceIndex uint32, endpoint [2]string) ([]string, error) {
	res, err := request(endpoint[0]+"?name="+url.QueryEscape(domain)+"&type=A", endpoint[1], interfaceIndex,
		4*time.Second, 64_000, "application/dns-json")
	if err != nil {
		return nil, err
	}
	var reply struct {
		Status int
		Answer []struct {
			Type int
			Data string
		}
	}
	if res.status != 200 || json.Unmarshal(res.body, &reply) != nil || reply.Status != 0 {
		return nil, fmt.Errorf("DNS: HTTP %d, статус %d", res.status, reply.Status)
	}
	var addresses []string
	for _, record := range reply.Answer {
		if record.Type == 1 {
			addresses = append(addresses, record.Data)
		}
	}
	return addresses, nil
}
