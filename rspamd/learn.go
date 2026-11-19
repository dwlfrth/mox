package rspamd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"sync"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
)

// Learn trains the Bayes classifier of rspamd with msg, as spam or as ham
// (non-spam), through the learnspam or learnham endpoint of the controller.
//
// rspamd refuses to learn a message it has already learned in the same class,
// which is returned as an error. rspamd responds to that with HTTP status 208, so
// any response without success is an error.
func Learn(ctx context.Context, conf config.Rspamd, spam bool, msg io.Reader) error {
	path := "/learnham"
	if spam {
		path = "/learnspam"
	}
	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := post(ctx, conf, path, nil, msg, &result); err != nil {
		return err
	}
	if result.Error != "" {
		return fmt.Errorf("rspamd: %s", result.Error)
	} else if !result.Success {
		return errors.New("rspamd: training not successful")
	}
	return nil
}

// Size of the queue of messages to learn. Large enough for a user moving many
// messages at once.
const learnQueueSize = 1000

type learnJob struct {
	log  mlog.Log
	conf config.Rspamd
	spam bool
	open func() (io.ReadCloser, error)
}

var (
	learnQueue     = make(chan learnJob, learnQueueSize)
	learnStartOnce sync.Once
)

// QueueLearn queues training rspamd with a message, see Learn. Messages are sent
// to rspamd one at a time, in the background, so a slow or unavailable rspamd does
// not slow down the caller. open is called when the message is sent, and must
// return the message.
//
// Training is best-effort: errors are logged, a message is dropped if the queue
// is full, and queued messages are lost when mox stops.
func QueueLearn(log mlog.Log, conf config.Rspamd, spam bool, open func() (io.ReadCloser, error)) {
	learnStartOnce.Do(func() {
		go learnWorker()
	})
	select {
	case learnQueue <- learnJob{log, conf, spam, open}:
	default:
		log.Error("rspamd learn queue full, not training rspamd with message", slog.Bool("spam", spam))
	}
}

func learnWorker() {
	for job := range learnQueue {
		learnOne(job)
	}
}

func learnOne(job learnJob) {
	log := job.log
	defer func() {
		x := recover()
		if x != nil {
			log.Error("unhandled panic while training rspamd", slog.Any("x", x))
			debug.PrintStack()
			metrics.PanicInc(metrics.Rspamd)
		}
	}()

	msg, err := job.open()
	if err != nil {
		log.Errorx("opening message for training rspamd", err, slog.Bool("spam", job.spam))
		return
	}
	defer func() {
		err := msg.Close()
		log.Check(err, "closing message after training rspamd")
	}()
	// The HTTP client closes a request body that is an io.Closer. We close msg
	// ourselves above, so hide its Close.
	err = Learn(context.Background(), job.conf, job.spam, io.NopCloser(msg))
	if err != nil {
		// Commonly because rspamd already learned the message.
		log.Infox("training rspamd", err, slog.Bool("spam", job.spam))
		return
	}
	log.Debug("trained rspamd", slog.Bool("spam", job.spam))
}
