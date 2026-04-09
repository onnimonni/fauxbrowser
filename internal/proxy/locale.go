package proxy

import (
	"math/rand"
	"strings"
)

// AcceptLanguageForHost returns a Chrome-realistic Accept-Language
// header value based on the target hostname's TLD. European ccTLDs
// get their country's primary language; generic TLDs (.com, .org,
// .net, .io, etc.) get a random Nordic/Baltic locale to match the
// user profile of someone browsing from our VPN exit region.
//
// Chrome's format: {lang}-{CC},{lang};q=0.9,en-US;q=0.8,en;q=0.7
//
// The caller's own Accept-Language (if set) is NOT overwritten —
// this function is only called when the header is empty.
func AcceptLanguageForHost(hostname string) string {
	tld := extractTLD(hostname)
	if v, ok := tldAcceptLanguage[tld]; ok {
		return v
	}
	return randomNordicLang()
}

// extractTLD returns the last dot-separated segment of a hostname,
// lowercased. Returns "" for bare hostnames or IPs.
func extractTLD(hostname string) string {
	// Strip port if present (shouldn't be, but defensive).
	if i := strings.LastIndex(hostname, ":"); i != -1 {
		hostname = hostname[:i]
	}
	if i := strings.LastIndex(hostname, "."); i != -1 {
		return strings.ToLower(hostname[i+1:])
	}
	return ""
}

// tldAcceptLanguage maps European country-code TLDs to a Chrome-
// realistic Accept-Language value. Format follows what a real
// Chrome user in that country would send.
var tldAcceptLanguage = map[string]string{
	// Nordic
	"fi": "fi-FI,fi;q=0.9,en-US;q=0.8,en;q=0.7",
	"se": "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7",
	"no": "nb-NO,nb;q=0.9,en-US;q=0.8,en;q=0.7",
	"dk": "da-DK,da;q=0.9,en-US;q=0.8,en;q=0.7",
	"is": "is-IS,is;q=0.9,en-US;q=0.8,en;q=0.7",

	// Baltic
	"ee": "et-EE,et;q=0.9,en-US;q=0.8,en;q=0.7",
	"lt": "lt-LT,lt;q=0.9,en-US;q=0.8,en;q=0.7",
	"lv": "lv-LV,lv;q=0.9,en-US;q=0.8,en;q=0.7",

	// Western Europe
	"de": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
	"at": "de-AT,de;q=0.9,en-US;q=0.8,en;q=0.7",
	"ch": "de-CH,de;q=0.9,en-US;q=0.8,en;q=0.7",
	"nl": "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7",
	"be": "nl-BE,nl;q=0.9,en-US;q=0.8,en;q=0.7",
	"fr": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
	"es": "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
	"it": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
	"pt": "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7",

	// Central/Eastern Europe
	"pl": "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7",
	"cz": "cs-CZ,cs;q=0.9,en-US;q=0.8,en;q=0.7",
	"sk": "sk-SK,sk;q=0.9,en-US;q=0.8,en;q=0.7",
	"hu": "hu-HU,hu;q=0.9,en-US;q=0.8,en;q=0.7",
	"ro": "ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7",
	"bg": "bg-BG,bg;q=0.9,en-US;q=0.8,en;q=0.7",
	"hr": "hr-HR,hr;q=0.9,en-US;q=0.8,en;q=0.7",
	"si": "sl-SI,sl;q=0.9,en-US;q=0.8,en;q=0.7",
	"gr": "el-GR,el;q=0.9,en-US;q=0.8,en;q=0.7",

	// English-speaking
	"uk": "en-GB,en;q=0.9,en-US;q=0.8",
	"ie": "en-IE,en;q=0.9,en-US;q=0.8",
}

// nordicBalticPool is the pool for random Accept-Language values
// used on generic TLDs (.com, .org, .net, etc.). Weighted toward
// Nordic/Baltic since our VPN exits are in that region.
var nordicBalticPool = []string{
	"fi-FI,fi;q=0.9,en-US;q=0.8,en;q=0.7",
	"sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7",
	"nb-NO,nb;q=0.9,en-US;q=0.8,en;q=0.7",
	"da-DK,da;q=0.9,en-US;q=0.8,en;q=0.7",
	"et-EE,et;q=0.9,en-US;q=0.8,en;q=0.7",
	"lt-LT,lt;q=0.9,en-US;q=0.8,en;q=0.7",
	"lv-LV,lv;q=0.9,en-US;q=0.8,en;q=0.7",
}

func randomNordicLang() string {
	return nordicBalticPool[rand.Intn(len(nordicBalticPool))]
}
