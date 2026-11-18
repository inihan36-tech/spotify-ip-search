//go:build windows

package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestWriteHostsPreservesUnrelatedEntries(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "hosts")
	original := []byte("\xef\xbb\xbf# note\r\n127.0.0.1 localhost\r\n1.1.1.1 OPEN.SPOTIFY.COM. preserved.test # comment\r\n2.2.2.2 open.spotify.com\r\n3.3.3.3 i.scdn.co")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := writeHosts(path, "48.102.233.174", []string{"open.spotify.com"}); err != nil {
			t.Fatal(err)
		}
	}
	want := []byte("\xef\xbb\xbf# note\r\n127.0.0.1 localhost\r\n1.1.1.1 preserved.test # comment\r\n3.3.3.3 i.scdn.co\r\n48.102.233.174 open.spotify.com\r\n")
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unexpected hosts contents %q (%v)", got, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected extra files: %v (%v)", entries, err)
	}
}

func TestDNSReplyMatchesQuery(t *testing.T) {
	query := dnsQuery("open.spotify.com", 7)
	reply := dnsQuery("open.spotify.com", 7)
	reply.Response = true
	reply.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: reply.Questions[0].Name, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: [4]byte{151, 101, 3, 42}},
	}}
	encode := func() []byte {
		t.Helper()
		data, err := reply.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if addresses, err := dnsReply(query, encode()); err != nil || strings.Join(addresses, ",") != "151.101.3.42" {
		t.Fatalf("unexpected answer %v (%v)", addresses, err)
	}
	reply.Questions[0].Name = dnsmessage.MustNewName("example.test.")
	if _, err := dnsReply(query, encode()); err == nil {
		t.Fatal("accepted an answer to an unrelated question")
	}
}

func TestOnlyWebCacheIsRemoved(t *testing.T) {
	local := t.TempDir()
	root := filepath.Join(local, "Spotify")
	for _, path := range []string{"Browser/Cache", "Default/Code Cache", "Browser/Local Storage", "Storage"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := webCache(local, "")
	if err != nil || removed != 2 {
		t.Fatalf("removed %d directories (%v)", removed, err)
	}
	for _, path := range []string{"Browser/Local Storage", "Storage"} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSourcesAndServiceResponses(t *testing.T) {
	if len(targetDomains) != 17 || len(config.Published) <= 34 {
		t.Fatal("incomplete built-in sources")
	}
	seen := make(map[string]bool)
	for _, ip := range config.Published {
		if publicIP(ip) != ip || seen[ip] {
			t.Fatalf("invalid or duplicate candidate %q", ip)
		}
		seen[ip] = true
	}
	if got := listedHostsIPs("127.0.0.1 open.spotify.com\n48.102.233.174 open.spotify.com\n8.8.8.8 unlisted.test"); strings.Join(got, ",") != "48.102.233.174" {
		t.Fatal(got)
	}
	if got := discussionIPs("<p>48.102.233.174 <a>open.spotify.com</a></p><script>8.8.8.8 open.spotify.com</script>"); strings.Join(got, ",") != "48.102.233.174" {
		t.Fatal(got)
	}
	check := response{status: 401, headers: http.Header{"Www-Authenticate": {`Bearer realm="spotify"`}}}
	if !validSpotifyResponse("spclient.wg.spotify.com", check) || validSpotifyResponse("open.spotify.com", check) {
		t.Fatal("incorrect result for unauthenticated service response")
	}
	if !compareVersion("v1.10.0", "1.9.0") || compareVersion("v1.1.0", "1.1.0") || compareVersion("v1.2.0-beta", "1.1.0") {
		t.Fatal("unexpected release comparison")
	}
}
