// Package rspamd is a minimal client for the HTTP API of the rspamd spam
// filtering system, for checking incoming messages.
//
// See https://docs.rspamd.com/developers/protocol/.
package rspamd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mjl-/mox/config"
)

// DefaultTimeout is used for requests when the configuration has no timeout.
const DefaultTimeout = 15 * time.Second

// Action is the action rspamd recommends for a message.
type Action string

// Actions known to rspamd by default.
const (
	ActionReject         Action = "reject"
	ActionSoftReject     Action = "soft reject"
	ActionRewriteSubject Action = "rewrite subject"
	ActionAddHeader      Action = "add header"
	ActionGreylist       Action = "greylist"
	ActionNoAction       Action = "no action"
)

// Symbol is a rule that matched for a message, with its contribution to the
// score.
type Symbol struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// Result is the outcome of checking a message.
type Result struct {
	IsSkipped     bool              `json:"is_skipped"` // If set, rspamd did not run all checks: due to its settings (Action "no action"), or because a prefilter such as GTUBE decided early (Action holds the verdict).
	Action        Action            `json:"action"`
	Score         float64           `json:"score"`
	RequiredScore float64           `json:"required_score"`
	Symbols       map[string]Symbol `json:"symbols"`
}

// Request holds the SMTP transaction details for a message, passed to rspamd as
// request headers.
type Request struct {
	IP       net.IP
	Helo     string   // Domain or address literal from EHLO/HELO.
	MailFrom string   // SMTP MAIL FROM address, empty for the null sender.
	Rcpts    []string // SMTP RCPT TO addresses.
	Hostname string   // Verified reverse DNS name of IP, empty if unknown.
	QueueID  string   // For correlating rspamd logs with mox logs.
}

// Check sends msg to the checkv2 endpoint of rspamd and returns its result.
//
// Errors never include the URL or password from the configuration.
func Check(ctx context.Context, conf config.Rspamd, req Request, msg io.Reader) (Result, error) {
	hdr := http.Header{}
	hdr.Set("IP", req.IP.String())
	if req.Helo != "" {
		hdr.Set("Helo", req.Helo)
	}
	// The null sender is passed as "<>", as MTAs like postfix do.
	if req.MailFrom == "" {
		hdr.Set("From", "<>")
	} else {
		hdr.Set("From", req.MailFrom)
	}
	for _, rcpt := range req.Rcpts {
		hdr.Add("Rcpt", rcpt)
	}
	// Like postfix, "unknown" when reverse DNS did not verify.
	if req.Hostname != "" {
		hdr.Set("Hostname", req.Hostname)
	} else {
		hdr.Set("Hostname", "unknown")
	}
	if req.QueueID != "" {
		hdr.Set("Queue-Id", req.QueueID)
	}

	var r Result
	if err := post(ctx, conf, "/checkv2", hdr, msg, &r); err != nil {
		return Result{}, err
	}
	return r, nil
}

// httpClient does not follow redirects: they would send the Password header to
// the redirect target. A redirect is returned as an error by post.
var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// post sends body to path on the rspamd server and parses a JSON response into
// result.
func post(ctx context.Context, conf config.Rspamd, path string, hdr http.Header, body io.Reader, result any) error {
	timeout := conf.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(conf.URL, "/")+path, body)
	if err != nil {
		return fmt.Errorf("new request: %w", stripURL(err))
	}
	for k, vl := range hdr {
		req.Header[k] = vl
	}
	if conf.Password != "" {
		req.Header.Set("Password", conf.Password)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to rspamd: %w", stripURL(err))
	}
	defer resp.Body.Close()

	// Responses are small JSON documents, symbols included.
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("reading response from rspamd: %w", stripURL(err))
	}
	if resp.StatusCode/100 != 2 {
		// rspamd returns errors as {"error": "..."}. We include only that field, not the
		// whole body or response headers.
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(buf, &e) == nil && e.Error != "" {
			return fmt.Errorf("rspamd: http status %d: %s", resp.StatusCode, e.Error)
		}
		return fmt.Errorf("rspamd: http status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(buf, result); err != nil {
		return fmt.Errorf("parsing response from rspamd: %w", err)
	}
	return nil
}

// stripURL returns the error wrapped in a url.Error, whose message includes the
// URL, which can hold sensitive information.
func stripURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}
