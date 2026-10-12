package graph

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// THE SELF HEADER IS SIGNED
//
// Until 1.3 the value of SelfHeader was the sending mailbox, and any message
// carrying the header at all was treated as the fleet's own. Anybody able to
// mail the inbox could set it. cti-agent then skipped the message unread and
// cti-mailbox archived it out of the inbox - an advisory, or a phish someone
// wanted out of sight, moved away by the fleet on the sender's say-so.
//
// The value is now
//
//	<mailbox>; n=<nonce>; sig=<hmac>
//
// with sig = HMAC-SHA256(key, lower(mailbox) + "\x00" + nonce) and the key
// derived from the app registration's client secret, which only this fleet
// holds. A header without a valid signature is ignored: the message is
// treated exactly as if it carried no header.
//
// What it does not stop: someone who can read one of our reports copying its
// header onto a message of their own. Every recipient of a report is on an
// allowlist and inside the organisation, and the mailbox the reports land in
// is one they can already archive mail in by hand.
//
// Rotating the client secret invalidates the signatures on mail already in
// the inbox. Those messages fall back to the sender check for the digest, and
// cti-mailbox leaves them for the operator rather than archiving them.

const selfSigContext = "cti-agent/self-header/v1\x00"

// selfKey derives the signing key. Derived rather than the secret itself, so
// the HMAC never takes the credential as its key directly.
func selfKey(secret string) []byte {
	k := sha256.Sum256([]byte(selfSigContext + secret))
	return k[:]
}

func selfMAC(secret, mailbox, nonce string) string {
	m := hmac.New(sha256.New, selfKey(secret))
	_, _ = m.Write([]byte(strings.ToLower(strings.TrimSpace(mailbox)) + "\x00" + nonce))
	return hex.EncodeToString(m.Sum(nil))
}

// signSelfHeader builds the header value for mail sent as mailbox. An empty
// secret yields the bare mailbox, which no reader will verify.
func signSelfHeader(secret, mailbox string) string {
	if secret == "" {
		return mailbox
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return mailbox
	}
	nonce := hex.EncodeToString(b)
	return mailbox + "; n=" + nonce + "; sig=" + selfMAC(secret, mailbox, nonce)
}

// verifySelfHeader reports whether value is a header this fleet signed.
func verifySelfHeader(secret, value string) bool {
	if secret == "" {
		return false
	}
	parts := strings.Split(value, ";")
	if len(parts) != 3 {
		return false
	}
	mailbox := strings.TrimSpace(parts[0])
	nonce, okN := strings.CutPrefix(strings.TrimSpace(parts[1]), "n=")
	sig, okS := strings.CutPrefix(strings.TrimSpace(parts[2]), "sig=")
	if mailbox == "" || !okN || !okS || len(nonce) < 16 {
		return false
	}
	want := selfMAC(secret, mailbox, nonce)
	return hmac.Equal([]byte(strings.ToLower(sig)), []byte(want))
}
