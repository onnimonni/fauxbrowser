package chromedp

import "testing"

func TestVersionRegex(t *testing.T) {
	cases := map[string]int{
		"Chromium 146.0.7680.177\n":                    146,
		"Chromium 146.0.7680.177 snap\n":               146,
		"Google Chrome 146.0.7190.80 \n":               146,
		"Chromium 131.0.6778.85 Built on Ubuntu\n":     131,
		"Chromium 144.0.0.0\n":                         144,
	}
	for in, want := range cases {
		m := versionRe.FindStringSubmatch(in)
		if m == nil {
			t.Errorf("no match for %q", in)
			continue
		}
		if m[1] != itoa(want) {
			t.Errorf("major for %q = %q, want %d", in, m[1], want)
		}
	}
}

func TestVersionRegexNoMatch(t *testing.T) {
	cases := []string{
		"",
		"Chromium\n",
		"Chromium 146\n",
		"Chromium 146.0\n",
		"not a version string at all",
	}
	for _, in := range cases {
		if m := versionRe.FindStringSubmatch(in); m != nil {
			t.Errorf("expected no match for %q, got %v", in, m)
		}
	}
}

// itoa is the minimal int→ascii helper to avoid importing strconv in the
// test file just for the assertion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
