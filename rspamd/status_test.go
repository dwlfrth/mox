package rspamd

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mlog"
)

// metricValue returns the value of a counter or gauge, or the sample count of a
// histogram, from the default registry,
// for the metric with name and the label values (name/value pairs).
func metricValue(t *testing.T, name string, labels ...string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	Metrics:
		for _, m := range f.GetMetric() {
			for i := 0; i+1 < len(labels); i += 2 {
				var found bool
				for _, lp := range m.GetLabel() {
					if lp.GetName() == labels[i] && lp.GetValue() == labels[i+1] {
						found = true
					}
				}
				if !found {
					continue Metrics
				}
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue()
			}
			if h := m.GetHistogram(); h != nil {
				return float64(h.GetSampleCount())
			}
			return m.GetGauge().GetValue()
		}
	}
	return 0
}

func TestLearnStatus(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	learn := func(spam bool) {
		t.Helper()
		msg := &closeCounter{Reader: strings.NewReader("test\r\n")}
		learnOne(learnJob{
			log:  mlog.New("rspamd", nil),
			conf: config.Rspamd{URL: srv.URL},
			spam: spam,
			open: func() (io.ReadCloser, error) { return msg, nil },
		})
	}

	s0 := Local()
	okSpam0 := metricValue(t, "mox_rspamd_learn_total", "class", "spam", "result", "ok")
	failedHam0 := metricValue(t, "mox_rspamd_learn_total", "class", "ham", "result", "failed")

	status, body = http.StatusOK, `{"success":true}`
	learn(true)
	status, body = http.StatusAlreadyReported, `{"error":"<id@example.org> has been already learned as ham, ignore it"}`
	learn(false)

	s1 := Local()
	if s1.LearnOK != s0.LearnOK+1 || s1.LearnFailed != s0.LearnFailed+1 || s1.LearnDropped != s0.LearnDropped {
		t.Fatalf("got ok %d, failed %d, dropped %d, expected %d, %d, %d", s1.LearnOK, s1.LearnFailed, s1.LearnDropped, s0.LearnOK+1, s0.LearnFailed+1, s0.LearnDropped)
	}
	if !strings.Contains(s1.LastLearnError, "already learned") || !s1.LastLearnErrorTime.After(s0.LastLearnErrorTime) {
		t.Fatalf("got last learn error %q at %v, expected rspamd's error after %v", s1.LastLearnError, s1.LastLearnErrorTime, s0.LastLearnErrorTime)
	}
	if v := metricValue(t, "mox_rspamd_learn_total", "class", "spam", "result", "ok"); v != okSpam0+1 {
		t.Fatalf("metric for trained spam: got %v, expected %v", v, okSpam0+1)
	}
	if v := metricValue(t, "mox_rspamd_learn_total", "class", "ham", "result", "failed"); v != failedHam0+1 {
		t.Fatalf("metric for failed ham: got %v, expected %v", v, failedHam0+1)
	}
}

// A message is dropped when the queue is full, and the queue length is reported.
func TestLearnQueueFull(t *testing.T) {
	// Keep the worker from starting, so the queue is not drained. This lasts for the
	// rest of the test run of this package: other tests must call learnOne directly
	// instead of relying on the worker through QueueLearn.
	learnStartOnce.Do(func() {})

	for len(learnQueue) < cap(learnQueue) {
		learnQueue <- learnJob{}
	}
	defer func() {
		for len(learnQueue) > 0 {
			<-learnQueue
		}
	}()

	s0 := Local()
	if s0.LearnQueued != cap(learnQueue) || s0.LearnQueueSize != cap(learnQueue) {
		t.Fatalf("got queued %d of %d, expected full queue of %d", s0.LearnQueued, s0.LearnQueueSize, cap(learnQueue))
	}
	if v := metricValue(t, "mox_rspamd_learn_queue_length"); v != float64(cap(learnQueue)) {
		t.Fatalf("queue length metric: got %v, expected %d", v, cap(learnQueue))
	}
	dropped0 := metricValue(t, "mox_rspamd_learn_total", "class", "spam", "result", "dropped")

	QueueLearn(mlog.New("rspamd", nil), config.Rspamd{}, true, func() (io.ReadCloser, error) {
		t.Fatalf("message opened for a dropped job")
		return nil, nil
	})

	s1 := Local()
	if s1.LearnDropped != s0.LearnDropped+1 || s1.LastLearnError != "queue full" {
		t.Fatalf("got dropped %d and last error %q, expected %d and queue full", s1.LearnDropped, s1.LastLearnError, s0.LearnDropped+1)
	}
	if v := metricValue(t, "mox_rspamd_learn_total", "class", "spam", "result", "dropped"); v != dropped0+1 {
		t.Fatalf("metric for dropped spam: got %v, expected %v", v, dropped0+1)
	}
}

func TestActionKnown(t *testing.T) {
	for _, a := range []Action{ActionReject, ActionSoftReject, ActionRewriteSubject, ActionAddHeader, ActionGreylist, ActionNoAction} {
		if !a.Known() {
			t.Errorf("action %q not known", a)
		}
	}
	for _, a := range []Action{"", "discard", "Reject"} {
		if a.Known() {
			t.Errorf("action %q known", a)
		}
	}
}

// Each check request, also a failed one, is observed in the duration histogram.
func TestCheckDurationMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n0 := metricValue(t, "mox_rspamd_check_duration_seconds")
	_, err := Check(context.Background(), config.Rspamd{URL: srv.URL}, Request{IP: net.ParseIP("192.0.2.1")}, strings.NewReader("test\r\n"))
	if err == nil {
		t.Fatalf("expected error for http status 500")
	}
	if n := metricValue(t, "mox_rspamd_check_duration_seconds"); n != n0+1 {
		t.Fatalf("got %v observations, expected %v", n, n0+1)
	}
}
