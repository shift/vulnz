package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Client provides HTTP operations with rate limiting, retries, and connection pooling
type Client struct {
	pools       *poolManager
	rateLimiter *RateLimiter
	config      Config
}

// NewClient creates a new HTTP client with the given configuration
func NewClient(config Config) *Client {
	return &Client{
		pools:       newPoolManager(config.MaxConnsPerHost),
		rateLimiter: NewRateLimiter(config.RateLimitRPS),
		config:      config,
	}
}

// Get performs an HTTP GET request with retry logic and rate limiting
func (c *Client) Get(ctx context.Context, urlStr string) (*http.Response, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	host := parsedURL.Host
	if host == "" {
		return nil, fmt.Errorf("invalid URL: missing host")
	}

	retryConfig := RetryConfig{
		MaxRetries:     c.config.MaxRetries,
		InitialBackoff: c.config.InitialBackoff,
		MaxBackoff:     c.config.MaxBackoff,
		Multiplier:     2.0,
	}

	var lastErr error
	for attempt := 0; attempt <= retryConfig.MaxRetries; attempt++ {
		// Wait for rate limit
		if err := c.rateLimiter.Wait(ctx, host); err != nil {
			return nil, fmt.Errorf("rate limit wait: %w", err)
		}

		// Get connection pool for this host
		pool := c.pools.getPool(host)

		// Create request with context
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}

		// Set User-Agent if configured
		if c.config.UserAgent != "" {
			req.Header.Set("User-Agent", c.config.UserAgent)
		}

		// Set timeout on client
		pool.mu.Lock()
		pool.client.Timeout = c.config.Timeout
		pool.mu.Unlock()

		// Execute request
		resp, err := pool.client.Do(req)
		if err != nil {
			lastErr = err

			// Check if error is retryable
			if !shouldRetry(0, err) {
				return nil, fmt.Errorf("non-retryable error: %w", err)
			}

			// Backoff and retry
			if attempt < retryConfig.MaxRetries {
				backoff := calculateBackoff(attempt, retryConfig)
				select {
				case <-time.After(backoff):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			continue
		}

		// Check for rate limiting
		if resp.StatusCode == 429 || (resp.StatusCode == 503 && resp.Header.Get("Retry-After") != "") {
			// Parse Retry-After header
			if retryAfter, ok := handleRetryAfter(resp); ok {
				resp.Body.Close()

				// Check if we have retries left
				if attempt >= retryConfig.MaxRetries {
					return nil, fmt.Errorf("rate limited and no retries remaining (status %d)", resp.StatusCode)
				}

				// Wait for Retry-After duration
				select {
				case <-time.After(retryAfter):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			} else {
				// No Retry-After header, use exponential backoff
				resp.Body.Close()

				if attempt >= retryConfig.MaxRetries {
					return nil, fmt.Errorf("rate limited and no retries remaining (status %d)", resp.StatusCode)
				}

				backoff := calculateBackoff(attempt, retryConfig)
				select {
				case <-time.After(backoff):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}

		// Check for other retryable status codes
		if isRetryable(resp.StatusCode) {
			resp.Body.Close()

			if attempt >= retryConfig.MaxRetries {
				return nil, fmt.Errorf("retryable status %d and no retries remaining", resp.StatusCode)
			}

			backoff := calculateBackoff(attempt, retryConfig)
			select {
			case <-time.After(backoff):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Check for non-retryable errors (4xx except 429)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			return resp, checkResponse(resp)
		}

		// Check for server errors (5xx except 503/504)
		if resp.StatusCode >= 500 && resp.StatusCode != 503 && resp.StatusCode != 504 {
			return resp, checkResponse(resp)
		}

		// Success or non-error response
		return resp, nil
	}

	// Exhausted all retries
	if lastErr != nil {
		return nil, fmt.Errorf("exhausted retries after %d attempts: %w", retryConfig.MaxRetries+1, lastErr)
	}

	return nil, fmt.Errorf("exhausted retries after %d attempts", retryConfig.MaxRetries+1)
}

// Download downloads a file from the given URL to the destination path
func (c *Client) Download(ctx context.Context, urlStr string, dest string) error {
	// Perform GET request
	resp, err := c.Get(ctx, urlStr)
	if err != nil {
		return fmt.Errorf("download GET: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if err := checkResponse(resp); err != nil {
		return err
	}

	// Create destination file
	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create destination file: %w", err)
	}
	defer f.Close()

	// Copy response body to file
	_, err = io.Copy(f, resp.Body)
	if err != nil {
		// Clean up partial file on error
		os.Remove(dest)
		return fmt.Errorf("write to file: %w", err)
	}

	return nil
}

// Post performs an HTTP POST request with retry logic and rate limiting
func (c *Client) Post(ctx context.Context, urlStr string, contentType string, body io.Reader) (*http.Response, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	host := parsedURL.Host
	if host == "" {
		return nil, fmt.Errorf("invalid URL: missing host")
	}

	// Wait for rate limit
	if err := c.rateLimiter.Wait(ctx, host); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	// Get connection pool for this host
	pool := c.pools.getPool(host)

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set headers
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	// Set timeout on client
	pool.mu.Lock()
	pool.client.Timeout = c.config.Timeout
	pool.mu.Unlock()

	// Execute request
	resp, err := pool.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute POST: %w", err)
	}

	return resp, nil
}
