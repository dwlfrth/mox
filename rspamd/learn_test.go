package rspamd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mlog"
)

// closeCounter fails a second Close, like store.MsgReader.
type closeCounter struct {
	io.Reader
	closes int
}

func (c *closeCounter) Close() error {
	c.closes++
	if c.closes > 1 {
		return errors.New("already closed")
	}
	return nil
}

func TestLearn(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	conf := config.Rspamd{URL: srv.URL}

	test := func(xstatus int, xbody, expErr string) {
		t.Helper()
		status, body = xstatus, xbody
		err := Learn(context.Background(), conf, true, strings.NewReader("test\r\n"))
		if expErr == "" && err != nil || expErr != "" && (err == nil || !strings.Contains(err.Error(), expErr)) {
			t.Fatalf("status %d, body %s: got error %v, expected %q", xstatus, xbody, err, expErr)
		}
	}
	test(http.StatusOK, `{"success":true}`, "")
	// rspamd answers a message it already learned in the same class with status
	// 208, a 2xx status, and its message in the error field.
	test(http.StatusAlreadyReported, `{"error":"<id@example.org> has been already learned as spam, ignore it"}`, "already learned")
	test(http.StatusOK, `{"success":false}`, "not successful")
}

// A failed training, e.g. a message rspamd already learned, is logged as not
// trained, and the message is still closed once.
func TestLearnOneFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAlreadyReported)
		w.Write([]byte(`{"error":"<id@example.org> has been already learned as spam, ignore it"}`))
	}))
	defer srv.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	msg := &closeCounter{Reader: strings.NewReader("test\r\n")}
	learnOne(learnJob{
		log:  mlog.New("rspamd", logger),
		conf: config.Rspamd{URL: srv.URL},
		spam: true,
		open: func() (io.ReadCloser, error) { return msg, nil },
	})
	if msg.closes != 1 {
		t.Fatalf("message closed %d times, expected once", msg.closes)
	}
	out := logs.String()
	if !strings.Contains(out, "training rspamd") || !strings.Contains(out, "already learned") {
		t.Fatalf("missing log about failed training with rspamd's error, got:\n%s", out)
	}
	if strings.Contains(out, "trained rspamd") {
		t.Fatalf("failed training logged as trained:\n%s", out)
	}
}

func TestLearnOneClosesOnce(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		paths = append(paths, r.URL.Path)
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	msg := &closeCounter{Reader: strings.NewReader("test\r\n")}
	learnOne(learnJob{
		log:  mlog.New("rspamd", nil),
		conf: config.Rspamd{URL: srv.URL},
		spam: true,
		open: func() (io.ReadCloser, error) { return msg, nil },
	})
	if len(paths) != 1 || paths[0] != "/learnspam" {
		t.Fatalf("got requests for paths %v, expected one for /learnspam", paths)
	}
	// The HTTP client closes a request body that is an io.Closer, so learnOne must
	// not hand it the message as is, or its own close fails.
	if msg.closes != 1 {
		t.Fatalf("message closed %d times, expected once", msg.closes)
	}
}
