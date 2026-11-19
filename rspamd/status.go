package rspamd

import (
	"maps"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ResultFallback is the check result when mox's own junk filter decided instead
// of rspamd: rspamd could not be reached, returned an error or an unknown action,
// or skipped the message without a verdict.
const ResultFallback = "fallback"

// Training results.
const (
	learnOK      = "ok"
	learnFailed  = "failed"  // Includes rspamd refusing a message it already learned.
	learnDropped = "dropped" // Queue was full.
)

var (
	metricCheck = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_rspamd_check_total",
			Help: "Incoming messages checked with rspamd, by result: the rspamd action that was applied, or fallback when the junk filter decided instead.",
		},
		[]string{"result"},
	)
	metricCheckDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "mox_rspamd_check_duration_seconds",
			Help:    "Duration of requests to rspamd for checking a message, including failed requests.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20},
		},
	)
	metricLearn = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mox_rspamd_learn_total",
			Help: "Messages for training rspamd, by class (spam, ham) and result: ok, failed (including messages rspamd already learned), or dropped because the queue was full.",
		},
		[]string{"class", "result"},
	)
	_ = promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "mox_rspamd_learn_queue_length",
			Help: "Messages waiting to be sent to rspamd for training.",
		},
		func() float64 { return float64(len(learnQueue)) },
	)
)

// started is when this process started, approximately: when this package was
// initialized.
var started = time.Now()

// LocalStatus is the state of the rspamd integration in this mox process, since
// it started.
type LocalStatus struct {
	Since time.Time // When this process started, the counts below are since then.

	Checks             map[string]int64 // Messages checked, by result: rspamd action applied, or ResultFallback.
	LastCheckError     string           // Error of the last check that fell back to the junk filter.
	LastCheckErrorTime time.Time

	LearnQueued    int // Messages waiting to be sent for training.
	LearnQueueSize int // Capacity of the queue.
	LearnOK        int64
	LearnFailed    int64 // Includes messages rspamd already learned.
	LearnDropped   int64 // Not queued because the queue was full.

	LastLearnError     string
	LastLearnErrorTime time.Time
}

var local struct {
	sync.Mutex
	status LocalStatus
}

// Local returns the state of the rspamd integration in this process.
func Local() LocalStatus {
	local.Lock()
	defer local.Unlock()
	s := local.status
	s.Since = started
	s.Checks = maps.Clone(s.Checks)
	s.LearnQueued = len(learnQueue)
	s.LearnQueueSize = cap(learnQueue)
	return s
}

// CheckResult records the outcome of checking a message: result is the rspamd
// action that was applied, or ResultFallback with the error that caused it.
func CheckResult(result string, err error) {
	metricCheck.WithLabelValues(result).Inc()

	local.Lock()
	defer local.Unlock()
	if local.status.Checks == nil {
		local.status.Checks = map[string]int64{}
	}
	local.status.Checks[result]++
	if err != nil {
		local.status.LastCheckError = err.Error()
		local.status.LastCheckErrorTime = time.Now()
	}
}

func learnResult(spam bool, result string, err error) {
	class := "ham"
	if spam {
		class = "spam"
	}
	metricLearn.WithLabelValues(class, result).Inc()

	local.Lock()
	defer local.Unlock()
	switch result {
	case learnOK:
		local.status.LearnOK++
	case learnFailed:
		local.status.LearnFailed++
	case learnDropped:
		local.status.LearnDropped++
	}
	if err != nil {
		local.status.LastLearnError = err.Error()
		local.status.LastLearnErrorTime = time.Now()
	}
}
