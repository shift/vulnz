package date

import (
	"fmt"
	"strings"
	"time"
)

// NormalizeDate parses various date formats and returns a normalized YYYY-MM-DD string.
// It supports common date formats including:
//   - RFC3339: "2006-01-02T15:04:05Z07:00"
//   - RFC1123: "Mon, 02 Jan 2006 15:04:05 MST"
//   - ISO8601: "2006-01-02T15:04:05Z"
//   - Standard date: "2006-01-02"
//   - US date: "01/02/2006"
//   - Unix timestamp (seconds): "1609459200"
//
// Returns an error if the date string cannot be parsed.
func NormalizeDate(dateStr string) (string, error) {
	if dateStr == "" {
		return "", fmt.Errorf("date string is empty")
	}

	// Trim whitespace
	dateStr = strings.TrimSpace(dateStr)

	// List of date formats to try, ordered from most specific to least specific
	formats := []string{
		// RFC3339 and variants
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z0700",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",

		// RFC1123 and variants
		time.RFC1123,
		time.RFC1123Z,
		time.RFC822,
		time.RFC822Z,
		time.RFC850,

		// ISO8601 variants with timezone
		"2006-01-02 15:04:05 MST",
		"2006-01-02 15:04:05 UTC",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",

		// Common US formats
		"01/02/2006 15:04:05",
		"01/02/2006 15:04",
		"01/02/2006",
		"1/2/2006",

		// Other common formats
		"02-Jan-2006",
		"02-Jan-06",
		"2-Jan-2006",
		"2-Jan-06",
		"Jan 02, 2006",
		"Jan 2, 2006",
		"January 02, 2006",
		"January 2, 2006",

		// Debian-style dates (day month year without comma)
		"2 Jan 2006",
		"02 Jan 2006",
		"_2 Jan 2006", // Go uses _ for space padding

		// Date with time but different separators
		"2006/01/02 15:04:05",
		"2006/01/02",

		// UNIX timestamp formats (handled separately below)
	}

	// Try parsing with each format
	for _, format := range formats {
		if parsed, err := time.Parse(format, dateStr); err == nil {
			return parsed.Format("2006-01-02"), nil
		}
	}

	// Try parsing as Unix timestamp (seconds since epoch)
	// Check if it's all digits (with optional negative sign)
	// Only consider it a timestamp if it's longer than 5 digits to avoid false positives
	if isUnixTimestamp(dateStr) && len(dateStr) >= 8 {
		var timestamp int64
		if _, err := fmt.Sscanf(dateStr, "%d", &timestamp); err == nil {
			// Validate reasonable range (1970-2100)
			if timestamp > 0 && timestamp < 4102444800 {
				parsed := time.Unix(timestamp, 0)
				return parsed.Format("2006-01-02"), nil
			}
		}
	}

	// If all parsing attempts fail, return an error
	return "", fmt.Errorf("unable to parse date string: %q", dateStr)
}

// isUnixTimestamp checks if a string looks like a Unix timestamp
func isUnixTimestamp(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check if it starts with optional negative sign followed by digits
	start := 0
	if s[0] == '-' {
		start = 1
	}

	if start >= len(s) {
		return false
	}

	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
