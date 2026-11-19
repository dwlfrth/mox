package rspamd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mjl-/mox/config"
)

func TestCheck(t *testing.T) {
	ctx := context.Background()
	req := Request{IP: net.ParseIP("192.0.2.1")}

	var status int
	var body string
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header.Clone()
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	conf := config.Rspamd{URL: srv.URL + "/secretpath/"}

	status, body = http.StatusOK, `{"action":"add header","score":6.5,"required_score":15,"symbols":{"X":{"name":"X","score":6.5}}}`
	r, err := Check(ctx, conf, req, strings.NewReader("test\r\n"))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if r.Action != ActionAddHeader || r.Score != 6.5 || r.RequiredScore != 15 || r.Symbols["X"].Score != 6.5 {
		t.Fatalf("got result %#v", r)
	}
	// Null sender and unverified reverse DNS, as postfix passes them.
	if hdr.Get("From") != "<>" || hdr.Get("Hostname") != "unknown" || hdr.Get("Helo") != "" {
		t.Fatalf("got headers %v", hdr)
	}

	// Errors include rspamd's error message, but not other response data.
	status, body = http.StatusBadRequest, `{"error":"bad request","other":"data"}`
	_, err = Check(ctx, conf, req, strings.NewReader("test\r\n"))
	if err == nil || !strings.HasSuffix(err.Error(), ": bad request") || strings.Contains(err.Error(), "data") {
		t.Fatalf("got error %v, expected rspamd's error message only", err)
	}
	status, body = http.StatusBadRequest, `not json, data`
	_, err = Check(ctx, conf, req, strings.NewReader("test\r\n"))
	if err == nil || strings.Contains(err.Error(), "data") {
		t.Fatalf("got error %v, expected only http status", err)
	}

	// Redirects are not followed: the Password header would be sent to the target.
	var targetPassword string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetPassword = r.Header.Get("Password")
		w.Write([]byte(`{"action":"no action"}`))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.RedirectHandler(target.URL+"/checkv2", http.StatusFound))
	defer redirector.Close()
	_, err = Check(ctx, config.Rspamd{URL: redirector.URL, Password: "secret"}, req, strings.NewReader("test\r\n"))
	if err == nil || !strings.Contains(err.Error(), "http status 302") {
		t.Fatalf("got error %v, expected http status 302", err)
	}
	if targetPassword != "" {
		t.Fatalf("redirect target received the password")
	}

	// Connection errors do not include the URL.
	srv.Close()
	_, err = Check(ctx, conf, req, strings.NewReader("test\r\n"))
	if err == nil || strings.Contains(err.Error(), "secretpath") {
		t.Fatalf("got error %v, expected error without url", err)
	}
}
