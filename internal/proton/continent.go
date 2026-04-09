package proton

import "strings"

// Minimal ISO alpha-2 country code → continent map. Only countries where
// Proton actually offers free-tier servers are enumerated precisely; the
// rest fall through to "" and are rejected by the continent filter.
//
// Continent codes: AF, AN, AS, EU, NA, OC, SA.
var continentOf = map[string]string{
	// Europe (where most Proton free servers live)
	"AL": "EU", "AD": "EU", "AT": "EU", "BY": "EU", "BE": "EU", "BA": "EU",
	"BG": "EU", "HR": "EU", "CY": "EU", "CZ": "EU", "DK": "EU", "EE": "EU",
	"FI": "EU", "FR": "EU", "DE": "EU", "GR": "EU", "HU": "EU", "IS": "EU",
	"IE": "EU", "IT": "EU", "XK": "EU", "LV": "EU", "LI": "EU", "LT": "EU",
	"LU": "EU", "MT": "EU", "MD": "EU", "MC": "EU", "ME": "EU", "NL": "EU",
	"MK": "EU", "NO": "EU", "PL": "EU", "PT": "EU", "RO": "EU", "SM": "EU",
	"RS": "EU", "SK": "EU", "SI": "EU", "ES": "EU", "SE": "EU", "CH": "EU",
	"UA": "EU", "GB": "EU", "UK": "EU", "VA": "EU", "RU": "EU",
	// North America
	"CA": "NA", "US": "NA", "MX": "NA",
	// Asia
	"JP": "AS", "SG": "AS", "HK": "AS", "KR": "AS", "TW": "AS", "IN": "AS",
	"ID": "AS", "MY": "AS", "PH": "AS", "TH": "AS", "VN": "AS", "IL": "AS",
	"TR": "AS", "AE": "AS",
	// Oceania
	"AU": "OC", "NZ": "OC",
	// South America
	"BR": "SA", "AR": "SA", "CL": "SA", "CO": "SA", "PE": "SA",
	// Africa
	"ZA": "AF", "EG": "AF", "NG": "AF",
}

// ContinentOf returns the ISO continent code for a country, or "" if
// unknown.
func ContinentOf(country string) string {
	return continentOf[strings.ToUpper(country)]
}
