package queue

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

func TestOmitDKIMSignatures(t *testing.T) {
	_, cleanup := setup(t)
	defer cleanup()

	mf := prepareFile(t)
	defer os.Remove(mf.Name())
	defer mf.Close()

	resolver := dns.MockResolver{
		A: map[string][]string{"submission.example.": {"127.0.0.1"}},
	}

	// Shaped like the prefix the smtpserver stores for a submitted message: dkim
	// signatures folded over multiple lines, followed by other headers.
	const dkimSig = "DKIM-Signature: v=1; d=mox.example; s=test; i=mjl@mox.example;\r\n\ta=ed25519-sha256; t=1; h=From:To:Subject;\r\n\tbh=abc=; b=def\r\n"
	const dkimSigLower = "dkim-signature: v=1; d=mox.example; s=test2; i=mjl@mox.example;\r\n\ta=rsa-sha256; t=1; h=From:To:Subject; bh=abc=; b=ghi\r\n"
	const otherHdrs = "Authentication-Results: mox.example; auth=pass smtp.mailfrom=mjl@mox.example\r\n"
	prefix := []byte(dkimSig + dkimSigLower + otherHdrs)

	from := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}

	// Fake submission server, passing the message data it received over the channel,
	// and responding with dataCode to the message data.
	var dataCode int
	received := make(chan string, 1)
	fakeServer := func(server net.Conn) {
		defer server.Close()
		fmt.Fprintf(server, "220 mail.mox.example\r\n")
		br := bufio.NewReader(server)
		br.ReadString('\n') // EHLO
		fmt.Fprintf(server, "250-localhost\r\n")
		fmt.Fprintf(server, "250 AUTH PLAIN\r\n")
		br.ReadString('\n') // AUTH PLAIN
		fmt.Fprintf(server, "235 2.7.0 auth ok\r\n")
		br.ReadString('\n') // MAIL FROM
		fmt.Fprintf(server, "250 ok\r\n")
		br.ReadString('\n') // RCPT TO
		fmt.Fprintf(server, "250 ok\r\n")
		br.ReadString('\n') // DATA
		fmt.Fprintf(server, "354 continue\r\n")
		data, _ := io.ReadAll(smtp.NewDataReader(br))
		received <- string(data)
		fmt.Fprintf(server, "%d result\r\n", dataCode)
		br.ReadString('\n') // QUIT
		fmt.Fprintf(server, "221 ok\r\n")
	}
	smtpclient.DialHook = func(ctx context.Context, dialer smtpclient.Dialer, timeout time.Duration, addr string, laddr net.Addr) (net.Conn, error) {
		server, client := net.Pipe()
		go fakeServer(server)
		return client, nil
	}
	defer func() {
		smtpclient.DialHook = nil
	}()

	// Deliver one attempt for the message with id, returning the data the server received.
	attempt := func(id int64, code int) string {
		t.Helper()
		dataCode = code
		n, err := NextAttemptSet(ctxbg, Filter{IDs: []int64{id}}, time.Now())
		tcheck(t, err, "kick message")
		tcompare(t, n, 1)
		n = launchWork(pkglog, resolver, map[string]struct{}{})
		tcompare(t, n, 1)
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		var data string
		select {
		case data = <-received:
		case <-timer.C:
			t.Fatalf("no delivery within 3s")
		}
		select {
		case <-deliveryResults:
		case <-timer.C:
			t.Fatalf("no delivery result within 3s")
		}
		return data
	}

	add := func(toDomain string) Msg {
		t.Helper()
		to := smtp.Path{Localpart: "mjl", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: toDomain}}}
		qml := []Msg{MakeMsg(from, to, false, false, int64(len(prefix)+len(testmsg)), "<test@localhost>", prefix, nil, time.Now(), "test")}
		err := Add(ctxbg, pkglog, "mjl", mf, qml...) // Sets ID in qml.
		tcheck(t, err, "add message to queue")
		return qml[0]
	}

	expectSignatures := func(data string, exp bool) {
		t.Helper()
		var expData string
		if exp {
			expData = string(prefix) + testmsg
		} else {
			expData = otherHdrs + testmsg
		}
		if data != expData {
			t.Fatalf("got data:\n%q\nexpected:\n%q", data, expData)
		}
	}

	// Route without the option: signatures are delivered.
	qm := add("submit.example")
	expectSignatures(attempt(qm.ID, 250), true)

	// Route with the option: signatures are left out, other headers and message are
	// delivered as is.
	qm = add("omitdkim.example")
	expectSignatures(attempt(qm.ID, 250), false)

	// First attempt matches a route with the option, and fails. The stored message
	// must still have its signatures, and the second attempt matches a route without
	// the option, so it is delivered with signatures.
	qm = add("omitdkimfirst.example")
	expectSignatures(attempt(qm.ID, 451), false)
	m, err := bstore.QueryDB[Msg](ctxbg, DB).Get()
	tcheck(t, err, "get message after failed attempt")
	tcompare(t, m.Attempts, 1)
	tcompare(t, string(m.MsgPrefix), string(prefix))
	tcompare(t, m.Size, int64(len(prefix)+len(testmsg)))
	expectSignatures(attempt(qm.ID, 250), true)
}

func TestOmitDKIMSignaturesPrefix(t *testing.T) {
	test := func(prefix, exp string) {
		t.Helper()
		got := string(omitDKIMSignatures([]byte(prefix)))
		if got != exp {
			t.Fatalf("got %q, expected %q", got, exp)
		}
	}

	test("", "")
	test("Received: from x\r\n", "Received: from x\r\n")
	test("DKIM-Signature: a\r\n", "")
	test("DKIM-Signature: a\r\n\tb\r\n c\r\nX: y\r\n", "X: y\r\n")
	test("X: y\r\n\tz\r\nDKIM-Signature: a\r\n\tb\r\n", "X: y\r\n\tz\r\n")
	test("dkim-signature : a\r\nX: y\r\n", "X: y\r\n")
	// Similar names are kept.
	test("DKIM-Signature-X: a\r\nX-DKIM-Signature: b\r\n", "DKIM-Signature-X: a\r\nX-DKIM-Signature: b\r\n")
	test(strings.Repeat("DKIM-Signature: a\r\n", 3)+"X: y\r\n", "X: y\r\n")
}
