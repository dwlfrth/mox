package rspamd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mjl-/mox/config"
)

// Shape of a response from rspamd 4.3.0, shortened.
const statResponse = `{"version":"4.3.0","git_id":"25c9ecc95","uptime":14814,"read_only":false,"scanned":11,"learned":540,"actions":{"reject":4,"soft reject":0,"rewrite subject":0,"add header":3,"greylist":0,"no action":4},"scan_times":[0.497596,null],"spam_count":7,"ham_count":4,"connections":1,"control_connections":587,"total_learns":538,"statfiles":[{"revision":10,"users":1,"used":0,"total":0,"size":0,"symbol":"BAYES_SPAM","type":"redis","classifier":{"name":"bayes","type":"binary","per_user":false,"min_learns":200},"class":"spam"},{"revision":528,"users":1,"used":0,"total":0,"size":0,"symbol":"BAYES_HAM","type":"redis","classifier":{"name":"bayes","type":"binary","per_user":false,"min_learns":200},"class":"ham"}],"fuzzy_hashes":{"rspamd.com":7623561}}`

func TestGetStat(t *testing.T) {
	ctx := context.Background()

	var status int
	var body string
	var method, path, password string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, password = r.Method, r.URL.Path, r.Header.Get("Password")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	conf := config.Rspamd{URL: srv.URL + "/secretpath/", Password: "secret"}

	status, body = http.StatusOK, statResponse
	s, err := GetStat(ctx, conf)
	if err != nil {
		t.Fatalf("get stat: %v", err)
	}
	if method != http.MethodGet || path != "/secretpath/stat" || password != "secret" {
		t.Fatalf("got request %s %s with password %q", method, path, password)
	}
	if s.Version != "4.3.0" || s.Uptime != 14814 || s.Scanned != 11 || s.Learned != 540 || s.Actions["reject"] != 4 || s.Actions["no action"] != 4 {
		t.Fatalf("got stat %#v", s)
	}
	if len(s.Statfiles) != 2 {
		t.Fatalf("got %d statfiles, expected 2", len(s.Statfiles))
	}
	sf := s.Statfiles[0]
	if sf.Symbol != "BAYES_SPAM" || sf.Class != "spam" || sf.Learned() != 10 || sf.Classifier.Name != "bayes" || sf.Classifier.MinLearns != 200 {
		t.Fatalf("got statfile %#v", sf)
	}
	if s.Statfiles[1].Class != "ham" || s.Statfiles[1].Learned() != 528 {
		t.Fatalf("got statfile %#v", s.Statfiles[1])
	}

	// Errors include rspamd's error message, but not the URL.
	status, body = http.StatusForbidden, `{"error":"Unauthorized"}`
	_, err = GetStat(ctx, conf)
	if err == nil || !strings.HasSuffix(err.Error(), ": Unauthorized") || strings.Contains(err.Error(), "secretpath") {
		t.Fatalf("got error %v, expected rspamd's error without url", err)
	}

	// Redirects are not followed.
	status, body = http.StatusFound, ""
	_, err = GetStat(ctx, conf)
	if err == nil || !strings.Contains(err.Error(), "http status 302") {
		t.Fatalf("got error %v, expected http status 302", err)
	}

	srv.Close()
	_, err = GetStat(ctx, conf)
	if err == nil || strings.Contains(err.Error(), "secretpath") {
		t.Fatalf("got error %v, expected error without url", err)
	}
}
