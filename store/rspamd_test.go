package store

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/message"
	"github.com/mjl-/mox/mox-"
)

// Changing junk flags of existing messages trains rspamd, delivering messages and
// untraining does not.
func TestRspamdLearn(t *testing.T) {
	type learned struct {
		path, body string
	}
	learnc := make(chan learned, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		learnc <- learned{r.URL.Path, string(buf)}
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	os.RemoveAll("../testdata/store/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/store/mox.conf")
	mox.MustLoadConfig(true, false)
	mox.Conf.Static.Rspamd = &config.Rspamd{URL: srv.URL}
	defer func() {
		mox.Conf.Static.Rspamd = nil
	}()
	err := Init(ctxbg)
	tcheck(t, err, "init")
	defer func() {
		err := Close()
		tcheck(t, err, "close")
	}()
	defer Switchboard()()
	acc, err := OpenAccount(pkglog, "mjl", false)
	tcheck(t, err, "open account")
	defer func() {
		err = acc.Close()
		tcheck(t, err, "closing account")
		acc.WaitClosed()
	}()

	// Deliver a message with the given junk flag.
	deliver := func(subject string, junk bool) Message {
		t.Helper()
		msgFile, err := CreateMessageTemp(pkglog, "rspamd-test")
		tcheck(t, err, "create temp message file")
		defer CloseRemoveTempFile(pkglog, msgFile, "temp message file")
		mw := message.NewWriter(msgFile)
		_, err = mw.Write([]byte("Subject: " + subject + "\r\n\r\nbody\r\n"))
		tcheck(t, err, "write message")
		prefix := []byte("Received: test\r\n")
		m := Message{Received: time.Now(), Size: int64(len(prefix)) + mw.Size, MsgPrefix: prefix, Flags: Flags{Junk: junk}}
		acc.WithWLock(func() {
			conf, _ := acc.Conf()
			err = acc.DeliverDestination(pkglog, conf.Destinations["mjl"], &m, msgFile)
		})
		tcheck(t, err, "deliver")
		return m
	}

	// Set junk flags of message and retrain, as a move by a user does.
	setFlags := func(m *Message, junk, notjunk bool) {
		t.Helper()
		m.Junk, m.Notjunk = junk, notjunk
		err := acc.DB.Write(ctxbg, func(tx *bstore.Tx) error {
			l := []Message{*m}
			err := acc.RetrainMessages(ctxbg, pkglog, tx, l)
			*m = l[0]
			return err
		})
		tcheck(t, err, "retrain")
	}

	// Check the next message rspamd learned. Messages are learned in order, so
	// learning the expected message also means nothing was learned before it.
	expect := func(path, subject string) {
		t.Helper()
		select {
		case l := <-learnc:
			exp := "Received: test\r\nSubject: " + subject + "\r\n\r\nbody\r\n"
			if l.path != path || l.body != exp {
				t.Fatalf("got learn %s with %q, expected %s with %q", l.path, l.body, path, exp)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no learn request, expected %s", path)
		}
	}

	// Delivered with junk flag, trains our junk filter, but not rspamd.
	m1 := deliver("one", true)
	if m1.TrainedJunk == nil || !*m1.TrainedJunk {
		t.Fatalf("message not trained as junk by our junk filter")
	}

	// User marks as not junk.
	setFlags(&m1, false, true)
	expect("/learnham", "one")

	// Untraining only, e.g. move to a neutral mailbox, does not train rspamd.
	setFlags(&m1, false, false)

	// User marks as junk.
	setFlags(&m1, true, false)
	expect("/learnspam", "one")

	// Delivered without flags, then marked as not junk.
	m2 := deliver("two", false)
	setFlags(&m2, false, true)
	expect("/learnham", "two")

	select {
	case l := <-learnc:
		t.Fatalf("unexpected learn %s with %q", l.path, l.body)
	case <-time.After(100 * time.Millisecond):
	}
}
