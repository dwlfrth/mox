package webadmin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mox-"
)

func TestRspamdStatus(t *testing.T) {
	api := Admin{}
	orig := mox.Conf.Static.Rspamd
	defer func() {
		mox.Conf.Static.Rspamd = orig
	}()

	// Not configured: nothing else is set, and rspamd is not contacted.
	mox.Conf.Static.Rspamd = nil
	if api.RspamdConfigured(ctxbg) {
		t.Fatalf("rspamd configured without rspamd in config")
	}
	s := api.RspamdStatus(ctxbg)
	if s.Configured || s.URL != "" || s.Reachable {
		t.Fatalf("got status %#v without rspamd configured", s)
	}

	var password string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		password = r.Header.Get("Password")
		if r.Method != http.MethodGet || r.URL.Path != "/stat" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"version":"4.3.0","uptime":60,"scanned":11,"learned":540,"actions":{"reject":4,"no action":7},"statfiles":[{"revision":10,"symbol":"BAYES_SPAM","classifier":{"name":"bayes","min_learns":200},"class":"spam"},{"revision":528,"symbol":"BAYES_HAM","classifier":{"name":"bayes","min_learns":200},"class":"ham"}]}`))
	}))
	defer srv.Close()

	mox.Conf.Static.Rspamd = &config.Rspamd{URL: srv.URL, Password: "secret"}
	if !api.RspamdConfigured(ctxbg) {
		t.Fatalf("rspamd not configured with rspamd in config")
	}
	s = api.RspamdStatus(ctxbg)
	if !s.Configured || s.URL != srv.URL || !s.Reachable || s.Error != "" {
		t.Fatalf("got status %#v, expected configured and reachable", s)
	}
	if password != "secret" {
		t.Fatalf("got password %q in request to rspamd", password)
	}
	if s.Version != "4.3.0" || s.Uptime != 60 || s.Scanned != 11 || s.Learned != 540 {
		t.Fatalf("got status %#v", s)
	}
	expActions := []RspamdCount{{"no action", 7}, {"reject", 4}}
	if len(s.Actions) != len(expActions) || s.Actions[0] != expActions[0] || s.Actions[1] != expActions[1] {
		t.Fatalf("got actions %v, expected %v sorted by name", s.Actions, expActions)
	}
	expClasses := []RspamdClass{{"bayes", "BAYES_SPAM", "spam", 10, 200}, {"bayes", "BAYES_HAM", "ham", 528, 200}}
	if len(s.Classes) != 2 || s.Classes[0] != expClasses[0] || s.Classes[1] != expClasses[1] {
		t.Fatalf("got classes %v, expected %v", s.Classes, expClasses)
	}
	if s.Local.LearnQueueSize == 0 {
		t.Fatalf("missing training queue size in local status %#v", s.Local)
	}

	// Unreachable: the error is in the status, without the URL.
	srv.Close()
	mox.Conf.Static.Rspamd = &config.Rspamd{URL: srv.URL + "/secretpath"}
	s = api.RspamdStatus(ctxbg)
	if !s.Configured || s.Reachable || s.Error == "" || strings.Contains(s.Error, "secretpath") {
		t.Fatalf("got status %#v, expected unreachable with error without url", s)
	}
	if s.Local.LearnQueueSize == 0 {
		t.Fatalf("missing local status when rspamd is unreachable: %#v", s.Local)
	}
}
