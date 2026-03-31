package http

import (
	"fmt"
	"io"
	"net/http"
)

// ResponseError wraps HTTP error responses with details
type ResponseError struct {
	StatusCode int
	Status     string
	URL        string
	Body       string
}

// Error implements the error interface
func (e *ResponseError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d: %s (URL: %s, Body: %s)", e.StatusCode, e.Status, e.URL, e.Body)
	}
	return fmt.Sprintf("HTTP %d: %s (URL: %s)", e.StatusCode, e.Status, e.URL)
}

// checkResponse validates the HTTP response and returns an error if unsuccessful
func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Read response body for error details (limit to 1KB)
	var body string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if err == nil {
			body = string(bodyBytes)
		}
	}

	return &ResponseError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		URL:        resp.Request.URL.String(),
		Body:       body,
	}
}
