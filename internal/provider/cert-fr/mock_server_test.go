package certfr_test

import (
	"net/http"
	"net/http/httptest"
)

type mockRSSServer struct {
	server  *httptest.Server
	body    string
	status  int
	Address string
}

func newMockRSSServer(body string) *mockRSSServer {
	m := &mockRSSServer{body: body, status: 200}
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(m.status)
		w.Write([]byte(m.body))
	}))
	m.Address = m.server.URL
	return m
}

func newMockRSSServerError(status int) *mockRSSServer {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	return &mockRSSServer{
		server:  srv,
		Address: srv.URL,
		status:  status,
	}
}

func (m *mockRSSServer) HTTPClient() *http.Client {
	return m.server.Client()
}

func (m *mockRSSServer) Close() {
	m.server.Close()
}
