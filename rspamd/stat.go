package rspamd

import (
	"context"
	"net/http"

	"github.com/mjl-/mox/config"
)

// Stat is the status of rspamd, from the stat endpoint of its controller.
// Counts are since rspamd's statistics were last reset, not since it started.
type Stat struct {
	Version   string           `json:"version"`
	Uptime    int64            `json:"uptime"`  // Seconds.
	Scanned   int64            `json:"scanned"` // Messages checked.
	Learned   int64            `json:"learned"` // Messages learned, all classifiers and classes.
	Actions   map[string]int64 `json:"actions"` // Messages checked, by action.
	Statfiles []Statfile       `json:"statfiles"`
}

// Statfile holds statistics for one class of a classifier, e.g. the spam class of
// the Bayes classifier.
type Statfile struct {
	Symbol     string `json:"symbol"` // E.g. BAYES_SPAM.
	Class      string `json:"class"`  // E.g. spam or ham.
	Revision   int64  `json:"revision"`
	Classifier struct {
		Name      string `json:"name"`       // E.g. bayes.
		MinLearns int64  `json:"min_learns"` // Messages to learn in each class before the classifier is used.
	} `json:"classifier"`
}

// Learned returns the number of messages learned in this class. rspamd reports it
// as the revision of the statfile, refreshed periodically.
func (s Statfile) Learned() int64 {
	return s.Revision
}

// GetStat fetches the status of rspamd from the stat endpoint of its controller.
//
// Errors never include the URL or password from the configuration.
func GetStat(ctx context.Context, conf config.Rspamd) (Stat, error) {
	var s Stat
	if err := request(ctx, conf, http.MethodGet, "/stat", nil, nil, &s); err != nil {
		return Stat{}, err
	}
	return s, nil
}
