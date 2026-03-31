package http

import (
	"fmt"
	"io"
	"net/http"
)

const MaxResponseSize = 500 * 1024 * 1024

func ReadLimitedBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return body, nil
}
