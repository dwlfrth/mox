package smtpserver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/rspamd"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

// fakeRspamd records requests and responds with a fixed status and body.
type fakeRspamd struct {
	status int
	body   string
	delay  time.Duration

	sync.Mutex
	paths   []string
	headers []http.Header
	bodies  []string
}

func (f *fakeRspamd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	buf, _ := io.ReadAll(r.Body)
	f.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.headers = append(f.headers, r.Header.Clone())
	f.bodies = append(f.bodies, string(buf))
	f.Unlock()
	time.Sleep(f.delay)
	w.WriteHeader(f.status)
	w.Write([]byte(f.body))
}

func TestRspamd(t *testing.T) {
	// No PTR record: without rspamd, the junk filter rejects the message with a
	// temporary error due to the iprev failure, as in TestDelivery.
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
	}

	actionBody := func(action string) string {
		return `{"is_skipped":false,"action":"` + action + `","score":7.5,"required_score":15,"symbols":{"BAYES_SPAM":{"name":"BAYES_SPAM","score":5.1},"R_SPF_NA":{"name":"R_SPF_NA","score":0}}}`
	}
	// Shape of rspamd's response when a prefilter decides early, as measured with
	// rspamd 4.3.0 for GTUBE: skipped, but with a verdict.
	skippedBody := func(action string) string {
		return `{"is_skipped":true,"action":"` + action + `","score":15,"required_score":15,"symbols":{"GTUBE":{"name":"GTUBE","score":0}},"messages":{"smtp_message":"Gtube pattern"}}`
	}
	fallback := &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SeSys3Other0}

	// Count non-expunged messages in mailbox, 0 if the mailbox does not exist.
	count := func(ts *testserver, mailboxName string, junk bool) int {
		t.Helper()
		mb, err := bstore.QueryDB[store.Mailbox](ctxbg, ts.acc.DB).FilterNonzero(store.Mailbox{Name: mailboxName}).FilterEqual("Expunged", false).Get()
		if err == bstore.ErrAbsent {
			return 0
		}
		tcheck(t, err, "get mailbox")
		q := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).FilterNonzero(store.Message{MailboxID: mb.ID}).FilterEqual("Expunged", false)
		if junk {
			q.FilterEqual("Junk", true)
		}
		n, err := q.Count()
		tcheck(t, err, "count messages")
		return n
	}

	tests := []struct {
		name    string
		status  int
		body    string
		delay   time.Duration
		noJunk  bool                 // Remove the junk special-use role from the Junk mailbox.
		expErr  *smtpclient.Error    // Nil for accepted delivery.
		expMbox string               // Mailbox with the delivered message, for accepted delivery.
		check   func(ts *testserver) // Additional checks.
	}{
		{name: "no action", status: http.StatusOK, body: actionBody("no action"), expMbox: "Inbox"},
		{name: "add header", status: http.StatusOK, body: actionBody("add header"), expMbox: "Junk"},
		{name: "rewrite subject", status: http.StatusOK, body: actionBody("rewrite subject"), expMbox: "Junk"},
		{name: "reject", status: http.StatusOK, body: actionBody("reject"), expErr: &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7DeliveryUnauth1}},
		{name: "soft reject", status: http.StatusOK, body: actionBody("soft reject"), expErr: &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SePol7DeliveryUnauth1}},
		{name: "greylist", status: http.StatusOK, body: actionBody("greylist"), expErr: &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SePol7DeliveryUnauth1}},
		{name: "no junk mailbox", status: http.StatusOK, body: actionBody("add header"), noJunk: true, expErr: fallback},
		// Without a usable result, the junk filter decides as without rspamd.
		{name: "http error", status: http.StatusInternalServerError, body: `{"error":"internal"}`, expErr: fallback},
		{name: "bad json", status: http.StatusOK, body: `{`, expErr: fallback},
		{name: "skipped", status: http.StatusOK, body: `{"is_skipped":true,"action":"no action"}`, expErr: fallback},
		{name: "skipped without action", status: http.StatusOK, body: `{"is_skipped":true}`, expErr: fallback},
		{name: "skipped reject", status: http.StatusOK, body: skippedBody("reject"), expErr: &smtpclient.Error{Permanent: true, Code: smtp.C550MailboxUnavail, Secode: smtp.SePol7DeliveryUnauth1}},
		{name: "skipped soft reject", status: http.StatusOK, body: skippedBody("soft reject"), expErr: &smtpclient.Error{Permanent: false, Code: smtp.C451LocalErr, Secode: smtp.SePol7DeliveryUnauth1}},
		{name: "skipped add header", status: http.StatusOK, body: skippedBody("add header"), expMbox: "Junk"},
		{name: "unknown action", status: http.StatusOK, body: actionBody("discard"), expErr: fallback},
		{name: "timeout", status: http.StatusOK, body: actionBody("no action"), delay: 2 * time.Second, expErr: fallback},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRspamd{status: tc.status, body: tc.body, delay: tc.delay}
			srv := httptest.NewServer(fake)
			defer srv.Close()

			ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
			defer ts.close()
			mox.Conf.Static.Rspamd = &config.Rspamd{URL: srv.URL + "/", Password: "secret", Timeout: time.Second}
			defer func() {
				mox.Conf.Static.Rspamd = nil
			}()

			if tc.noJunk {
				_, err := bstore.QueryDB[store.Mailbox](ctxbg, ts.acc.DB).FilterNonzero(store.Mailbox{Name: "Junk"}).UpdateField("Junk", false)
				tcheck(t, err, "clear junk special-use")
			}

			ts.run(func(client *smtpclient.Client) {
				err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false, false)
				if tc.expErr == nil {
					tcheck(t, err, "deliver")
				} else {
					ts.smtpErr(err, tc.expErr)
				}
			})

			if tc.expMbox != "" {
				if n := count(ts, tc.expMbox, tc.expMbox == "Junk"); n != 1 {
					t.Fatalf("got %d messages in %s (junk flag set if Junk), expected 1", n, tc.expMbox)
				}
			}

			fake.Lock()
			defer fake.Unlock()
			if len(fake.paths) != 1 || fake.paths[0] != "/checkv2" {
				t.Fatalf("got requests for paths %v, expected one for /checkv2", fake.paths)
			}
			h := fake.headers[0]
			exp := map[string]string{
				"Password": "secret",
				"Ip":       "127.0.0.10",
				"Helo":     "mox.example",
				"From":     "remote@example.org",
				"Rcpt":     "mjl@mox.example",
				"Hostname": "unknown",
			}
			for k, v := range exp {
				if got := h.Get(k); got != v {
					t.Errorf("header %s: got %q, expected %q", k, got, v)
				}
			}
			if h.Get("Queue-Id") == "" {
				t.Errorf("missing Queue-Id header")
			}
			if fake.bodies[0] != deliverMessage {
				t.Errorf("got message %q, expected %q", fake.bodies[0], deliverMessage)
			}
		})
	}
}

// Rspamd is called once for a message with multiple recipients, with all
// recipients, and with the verified reverse DNS name.
func TestRspamdMultipleRecipients(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."},
		},
		// Without SPF pass, mox accepts only one recipient.
		TXT: map[string][]string{
			"example.org.": {"v=spf1 ip4:127.0.0.10 -all"},
		},
	}

	fake := &fakeRspamd{status: http.StatusOK, body: `{"action":"no action","score":0,"required_score":15}`}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()
	mox.Conf.Static.Rspamd = &config.Rspamd{URL: srv.URL}
	defer func() {
		mox.Conf.Static.Rspamd = nil
	}()

	rcpts := []string{"mjl@mox.example", "o@mox.example", "móx@mox.example"}
	ts.run(func(client *smtpclient.Client) {
		_, err := client.DeliverMultiple(ctxbg, "remote@example.org", rcpts, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, true, false)
		tcheck(t, err, "deliver")
	})

	fake.Lock()
	defer fake.Unlock()
	if len(fake.paths) != 1 {
		t.Fatalf("got %d requests to rspamd, expected 1", len(fake.paths))
	}
	h := fake.headers[0]
	if got := h.Values("Rcpt"); strings.Join(got, ",") != strings.Join(rcpts, ",") {
		t.Errorf("got rcpt headers %q, expected %q", got, rcpts)
	}
	if got := h.Get("Hostname"); got != "example.org" {
		t.Errorf("got hostname %q, expected example.org", got)
	}
	if got := h.Get("Password"); got != "" {
		t.Errorf("got password header %q without password configured", got)
	}
}

// The symbols in X-Mox-Reason are the 10 with the largest absolute score, ties
// sorted by name.
func TestRspamdSymbols(t *testing.T) {
	symbols := map[string]rspamd.Symbol{}
	for i, name := range []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"} {
		symbols[name] = rspamd.Symbol{Score: float64(i + 1)}
	}
	symbols["NEG"] = rspamd.Symbol{Score: -20}
	symbols["TIE_B"] = rspamd.Symbol{Score: 5}
	symbols["ZERO"] = rspamd.Symbol{Score: 0}
	got := rspamdSymbols(symbols)
	exp := "NEG -20.00, J 10.00, I 9.00, H 8.00, G 7.00, F 6.00, E 5.00, TIE_B 5.00, D 4.00, C 3.00"
	if got != exp {
		t.Fatalf("got %q, expected %q", got, exp)
	}
	if got := rspamdSymbols(nil); got != "(none)" {
		t.Fatalf("got %q for no symbols, expected (none)", got)
	}
}

// A client that greets with an IP address literal, e.g. "EHLO [127.0.0.10]", is
// passed to rspamd as that address literal.
func TestRspamdHeloAddressLiteral(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
	}

	fake := &fakeRspamd{status: http.StatusOK, body: `{"action":"no action","score":0,"required_score":15}`}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), resolver)
	defer ts.close()
	mox.Conf.Static.Rspamd = &config.Rspamd{URL: srv.URL}
	defer func() {
		mox.Conf.Static.Rspamd = nil
	}()

	ts.runRaw(func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		// Reads a possibly multiline reply, returning its last line.
		reply := func() string {
			for {
				line, err := br.ReadString('\n')
				tcheck(t, err, "read reply")
				if len(line) < 4 || line[3] != '-' {
					return strings.TrimRight(line, "\r\n")
				}
			}
		}
		cmd := func(s, expCode string) {
			t.Helper()
			_, err := fmt.Fprintf(conn, "%s\r\n", s)
			tcheck(t, err, "write command")
			if line := reply(); !strings.HasPrefix(line, expCode) {
				t.Fatalf("%s: got reply %q, expected code %s", s, line, expCode)
			}
		}
		if line := reply(); !strings.HasPrefix(line, "220") {
			t.Fatalf("got greeting %q", line)
		}
		cmd("EHLO [127.0.0.10]", "250")
		cmd("MAIL FROM:<remote@example.org>", "250")
		cmd("RCPT TO:<mjl@mox.example>", "250")
		cmd("DATA", "354")
		msg := strings.ReplaceAll(strings.TrimRight(deliverMessage, "\r\n"), "\n.", "\n..")
		cmd(msg+"\r\n.", "250")
		cmd("QUIT", "221")
	})

	fake.Lock()
	defer fake.Unlock()
	if len(fake.headers) != 1 {
		t.Fatalf("got %d requests to rspamd, expected 1", len(fake.headers))
	}
	if got := fake.headers[0].Get("Helo"); got != "[127.0.0.10]" {
		t.Fatalf("got helo header %q, expected [127.0.0.10]", got)
	}
}
