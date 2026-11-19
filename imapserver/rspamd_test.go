package imapserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mox-"
)

// Moving a message into Junk and setting $NotJunk trains rspamd. Without
// AutomaticJunkFlags, moving out of Junk does not change the junk flags, and does
// not train rspamd.
func TestRspamdLearn(t *testing.T) {
	learnc := make(chan string, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		learnc <- r.URL.Path
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	tc := start(t, false)
	defer tc.close()
	mox.Conf.Static.Rspamd = &config.Rspamd{URL: srv.URL}
	defer func() {
		mox.Conf.Static.Rspamd = nil
	}()

	// Messages are learned in order, so the expected learn also means nothing else
	// was learned before it.
	expect := func(path string) {
		t.Helper()
		select {
		case p := <-learnc:
			if p != path {
				t.Fatalf("got learn %s, expected %s", p, path)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no learn request, expected %s", path)
		}
	}

	tc.login("mjl@mox.example", password0)
	tc.client.Append("inbox", makeAppend(exampleMsg))

	tc.client.Select("inbox")
	tc.transactf("ok", "move 1 Junk")
	expect("/learnspam")

	tc.client.Select("Junk")
	tc.transactf("ok", "move 1 Inbox")

	tc.client.Select("inbox")
	tc.transactf("ok", `store 1 flags ($NotJunk)`)
	expect("/learnham")

	select {
	case p := <-learnc:
		t.Fatalf("unexpected learn %s", p)
	case <-time.After(100 * time.Millisecond):
	}
}
