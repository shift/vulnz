package utils

import (
	"context"
	"io"
)

// ContextReader wraps an io.Reader with periodic context cancellation checks.
// It checks ctx.Done() every N reads (configurable via interval) to avoid
// checking on every single Read call while still providing responsive cancellation.
type ContextReader struct {
	ctx      context.Context
	reader   io.Reader
	interval int64
	count    int64
}

// NewContextReader creates a new ContextReader that wraps the given reader
// and checks for context cancellation every `interval` reads.
func NewContextReader(ctx context.Context, r io.Reader, interval int64) *ContextReader {
	return &ContextReader{ctx: ctx, reader: r, interval: interval}
}

// Read implements io.Reader with periodic context cancellation checks.
func (cr *ContextReader) Read(p []byte) (int, error) {
	cr.count++
	if cr.count%cr.interval == 0 {
		select {
		case <-cr.ctx.Done():
			return 0, cr.ctx.Err()
		default:
		}
	}
	return cr.reader.Read(p)
}
