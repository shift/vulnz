package rpm

import (
	"strconv"
	"unicode"
)

// compareVersionParts compares two version or release strings using RPM's algorithm.
// This is a direct translation of RPM's rpmvercmp function from C to Go.
//
// The algorithm:
//  1. Check for tilde (~) which sorts before everything (pre-releases)
//  2. Skip non-alphanumeric characters
//  3. Extract segments of same type (all digits or all letters)
//  4. Compare segments:
//     - Numeric segments: compare as integers (after stripping leading zeros)
//     - Alpha segments: compare lexicographically
//     - Numeric segments beat empty alpha segments
//  5. If one string has more segments, compare based on remaining content
//
// Returns:
//   - -1 if v1 < v2
//   - 0 if v1 == v2
//   - 1 if v1 > v2
//
// Examples:
//   - compareVersionParts("1.2.3", "1.2.4")  -> -1
//   - compareVersionParts("1.10", "1.9")     -> 1  (numeric: 10 > 9)
//   - compareVersionParts("1.a", "1.b")      -> -1 (alpha: "a" < "b")
//   - compareVersionParts("1.0~rc1", "1.0")  -> -1 (tilde for pre-release)
func compareVersionParts(v1, v2 string) int {
	// Handle nil/empty cases
	if v1 == "" && v2 == "" {
		return 0
	}
	if v1 == "" {
		return -1
	}
	if v2 == "" {
		return 1
	}

	// Convert to rune slices for character-by-character processing
	r1 := []rune(v1)
	r2 := []rune(v2)
	i1, i2 := 0, 0

	// Loop through each version segment and compare them
	for i1 < len(r1) || i2 < len(r2) {
		// TILDE HANDLING: tilde sorts before everything, even end of string
		// Check for tilde at current position before skipping anything
		if i1 < len(r1) && r1[i1] == '~' {
			if i2 < len(r2) && r2[i2] == '~' {
				// Both have tilde, skip them and continue
				i1++
				i2++
				continue
			}
			// v1 has tilde, v2 doesn't -> v1 is less
			return -1
		}
		if i2 < len(r2) && r2[i2] == '~' {
			// v2 has tilde, v1 doesn't -> v2 is less
			return 1
		}

		// Skip non-alphanumeric characters (but not tilde, we handled it above)
		for i1 < len(r1) && !isAlphaNum(r1[i1]) && r1[i1] != '~' {
			i1++
		}
		for i2 < len(r2) && !isAlphaNum(r2[i2]) && r2[i2] != '~' {
			i2++
		}

		// If we ran to the end of either, we're finished
		if i1 >= len(r1) && i2 >= len(r2) {
			return 0
		}
		if i1 >= len(r1) {
			// v1 ended, check if v2 has only zeros left
			if hasOnlyZeros(r2[i2:]) {
				return 0
			}
			return -1
		}
		if i2 >= len(r2) {
			// v2 ended, check if v1 has only zeros left
			if hasOnlyZeros(r1[i1:]) {
				return 0
			}
			return 1
		}

		// Determine the type of the next segment in v1
		isNum1 := unicode.IsDigit(r1[i1])
		isNum2 := unicode.IsDigit(r2[i2])

		// Extract segment from v1
		start1 := i1
		if isNum1 {
			for i1 < len(r1) && unicode.IsDigit(r1[i1]) {
				i1++
			}
		} else {
			for i1 < len(r1) && unicode.IsLetter(r1[i1]) {
				i1++
			}
		}
		seg1 := string(r1[start1:i1])

		// Extract segment from v2 (must be same type if both exist)
		start2 := i2
		if isNum2 {
			for i2 < len(r2) && unicode.IsDigit(r2[i2]) {
				i2++
			}
		} else {
			for i2 < len(r2) && unicode.IsLetter(r2[i2]) {
				i2++
			}
		}
		seg2 := string(r2[start2:i2])

		// Handle type mismatch: numeric vs alpha
		// Numeric segments are always newer than alpha segments
		if isNum1 && !isNum2 {
			// v1 is numeric, v2 is alpha -> v1 is greater
			return 1
		}
		if !isNum1 && isNum2 {
			// v1 is alpha, v2 is numeric -> v2 is greater
			return -1
		}

		// Both segments are the same type, compare them
		cmpResult := compareSegment(seg1, seg2, isNum1)
		if cmpResult != 0 {
			return cmpResult
		}
	}

	// All segments compared equal
	return 0
}

// hasOnlyZeros checks if a rune slice contains only zeros and non-alphanumeric characters
func hasOnlyZeros(runes []rune) bool {
	for _, r := range runes {
		if unicode.IsDigit(r) && r != '0' {
			return false
		}
		if unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// compareSegment compares two segments of the same type (numeric or alpha).
//
// For numeric segments:
//   - Strip leading zeros
//   - Compare by length first (more digits = larger number)
//   - If same length, compare lexicographically
//
// For alpha segments:
//   - Compare lexicographically
//
// Returns: -1, 0, or 1
func compareSegment(seg1, seg2 string, isNumeric bool) int {
	if isNumeric {
		// Strip leading zeros for numeric comparison
		seg1 = stripLeadingZeros(seg1)
		seg2 = stripLeadingZeros(seg2)

		// Whichever number has more digits wins
		if len(seg1) > len(seg2) {
			return 1
		}
		if len(seg1) < len(seg2) {
			return -1
		}

		// Same length, compare as strings (works for numbers of same length)
		if seg1 > seg2 {
			return 1
		}
		if seg1 < seg2 {
			return -1
		}
		return 0
	}

	// Alpha comparison - lexicographic
	if seg1 > seg2 {
		return 1
	}
	if seg1 < seg2 {
		return -1
	}
	return 0
}

// stripLeadingZeros removes leading zeros from a numeric string.
// Returns "0" if the string is all zeros or empty.
func stripLeadingZeros(s string) string {
	if s == "" {
		return "0"
	}

	// Find first non-zero character
	i := 0
	for i < len(s) && s[i] == '0' {
		i++
	}

	// All zeros or empty
	if i >= len(s) {
		return "0"
	}

	return s[i:]
}

// isAlphaNum returns true if the rune is alphanumeric (letter or digit).
func isAlphaNum(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// isNumeric checks if a string contains only digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// splitVersion splits a version string into segments for analysis.
// This is primarily used for debugging and testing purposes.
//
// It splits on transitions between:
//   - Alphanumeric and non-alphanumeric characters
//   - Digits and letters
//
// Example:
//   - splitVersion("1.2a3") -> ["1", ".", "2", "a", "3"]
func splitVersion(v string) []string {
	if v == "" {
		return []string{}
	}

	var segments []string
	runes := []rune(v)
	start := 0

	for i := 1; i < len(runes); i++ {
		prevIsAlphaNum := isAlphaNum(runes[i-1])
		currIsAlphaNum := isAlphaNum(runes[i])
		prevIsDigit := unicode.IsDigit(runes[i-1])
		currIsDigit := unicode.IsDigit(runes[i])

		// Transition between alphanumeric and non-alphanumeric
		if prevIsAlphaNum != currIsAlphaNum {
			segments = append(segments, string(runes[start:i]))
			start = i
			continue
		}

		// Transition between digit and letter (both alphanumeric)
		if prevIsAlphaNum && currIsAlphaNum && prevIsDigit != currIsDigit {
			segments = append(segments, string(runes[start:i]))
			start = i
		}
	}

	// Add the last segment
	if start < len(runes) {
		segments = append(segments, string(runes[start:]))
	}

	return segments
}

// parseIntSafe safely parses a string as an integer, returning 0 on error.
// This is used internally for numeric segment comparison.
func parseIntSafe(s string) int {
	if s == "" {
		return 0
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}
