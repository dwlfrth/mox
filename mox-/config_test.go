package mox

import (
	"context"
	"strings"
	"testing"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/mlog"
)

func TestRspamdConfig(t *testing.T) {
	log := mlog.New("mox", nil)

	// Return the rspamd errors for the configuration, ignoring errors about the
	// otherwise empty static configuration.
	check := func(r config.Rspamd) []string {
		t.Helper()
		conf := Config{Static: config.Static{LogLevel: "info", Rspamd: &r}}
		var l []string
		for _, err := range PrepareStaticConfig(context.Background(), log, "mox.conf", &conf, true, false) {
			if strings.HasPrefix(err.Error(), "rspamd:") {
				l = append(l, err.Error())
			}
		}
		return l
	}

	good := []config.Rspamd{
		{URL: "http://localhost:11334"},
		{URL: "https://rspamd.example/base/", Password: "secret", Timeout: 1},
	}
	for _, r := range good {
		if errs := check(r); len(errs) != 0 {
			t.Errorf("url %q: got errors %v, expected none", r.URL, errs)
		}
	}

	bad := []config.Rspamd{
		{URL: ""},
		{URL: "localhost:11334"},
		{URL: "ftp://localhost"},
		{URL: "http://user:secret@localhost:11334"},
		{URL: "http://localhost:11334/?password=secret"},
		{URL: "http://localhost:11334/#secret"},
		{URL: "http://user:secret@localhost:badport"},
		{URL: "http://localhost:11334", Timeout: -1},
	}
	for _, r := range bad {
		errs := check(r)
		if len(errs) != 1 {
			t.Errorf("url %q, timeout %v: got errors %v, expected one", r.URL, r.Timeout, errs)
		}
		// The URL can hold a password, so it must not be in the error.
		for _, e := range errs {
			if strings.Contains(e, "secret") {
				t.Errorf("url %q: error %q includes password", r.URL, e)
			}
		}
	}
}
