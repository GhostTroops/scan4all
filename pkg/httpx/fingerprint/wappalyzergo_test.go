package wappalyzer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCookiesDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Set-Cookie": []string{"_uetsid=ABCDEF"},
	}, []byte(""))

	require.Contains(t, matches, "Microsoft Advertising", "Could not get correct match")
}

func TestHeadersDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	matches := wappalyzer.Fingerprint(map[string][]string{
		"Server": []string{"now"},
	}, []byte(""))

	require.Contains(t, matches, "Vercel", "Could not get correct match")
}

func TestBodyDetect(t *testing.T) {
	wappalyzer, err := New()
	require.Nil(t, err, "could not create wappalyzer")

	t.Run("meta", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html>
<head>
<meta name="generator" content="mura cms 1.2.0">
</head>
</html>`))
		require.Contains(t, matches, "Mura CMS", "Could not get correct match")
	})

	t.Run("html-implied", func(t *testing.T) {
		matches := wappalyzer.Fingerprint(map[string][]string{}, []byte(`<html data-ng-app="rbschangeapp">
<head>
</head>
<body>
</body>
</html>`))
		require.Contains(t, matches, "AngularJS", "Could not get correct implied match")
		require.Contains(t, matches, "PHP", "Could not get correct implied match")
		require.Contains(t, matches, "Proximis Unified Commerce", "Could not get correct match")
	})
}
