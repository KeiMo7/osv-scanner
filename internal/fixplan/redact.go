package fixplan

import (
	"net/url"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
)

var secretQueryParams = map[string]struct{}{
	"token":         {},
	"access_token":  {},
	"refresh_token": {},
	"api_key":       {},
	"apikey":        {},
	"key":           {},
	"password":      {},
	"passwd":        {},
	"secret":        {},
	"auth":          {},
}

var (
	// Match credential-like HTTP headers in wrapped errors.
	authorizationPattern = cachedregexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:bearer|basic|token)?\s*[^\s,"']+`)
	headerTokenPattern   = cachedregexp.MustCompile(`(?i)((?:x-[a-z0-9-]*(?:token|key|secret)|proxy-authorization)\s*[:=]\s*)[^\s,"']+`)
	urlUserInfoPattern   = cachedregexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)
)

// RedactText removes credentials from URLs and common auth-header forms.
// It is safe to call on error strings before they are stored or displayed.
func RedactText(s string) string {
	if s == "" {
		return s
	}

	// Redact query parameters first, while the URL still has its original
	// userinfo and can be parsed normally.
	s = cachedregexp.MustCompile(`https?://[^\s"'<>]+`).ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		q := u.Query()
		changed := false
		for k := range q {
			if _, ok := secretQueryParams[strings.ToLower(k)]; ok {
				q.Set(k, "<redacted>")
				changed = true
			}
		}
		if changed {
			u.RawQuery = q.Encode()
			raw = u.String()
		}

		return raw
	})
	s = urlUserInfoPattern.ReplaceAllString(s, "${1}<redacted>@")
	s = authorizationPattern.ReplaceAllString(s, "${1}<redacted>")
	s = headerTokenPattern.ReplaceAllString(s, "${1}<redacted>")

	return s
}

// RedactURL returns a URL string without userinfo or secret query values.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return RedactText(raw)
	}
	u.User = nil
	q := u.Query()
	for k := range q {
		if _, ok := secretQueryParams[strings.ToLower(k)]; ok {
			q.Set(k, "<redacted>")
		}
	}
	u.RawQuery = q.Encode()

	return u.String()
}
