package http

// Export functions for testing

// CalculateBackoff is exported for testing
var CalculateBackoff = calculateBackoff

// HandleRetryAfter is exported for testing
var HandleRetryAfter = handleRetryAfter

// IsRetryable is exported for testing
var IsRetryable = isRetryable

// ShouldRetry is exported for testing
var ShouldRetry = shouldRetry
