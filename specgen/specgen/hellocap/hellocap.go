// Package hellocap provides facilities for capturing TLS ClientHellos.
package hellocap

import (
	"crypto/tls"
	"net"
	"net/http"
)

// Server is a TLS server used to capture incoming ClientHellos. This is built specifically for the
// specgen use case. Performance is not prioritized and features are intentionally minimal.
type Server struct {
	s  http.Server
	hl *handlerListener
}

// NewServer creates a new hello-capturing HTTP server. In the provided handler, use FromRequest to
// obtain the TLS ClientHello provided by the client.
func NewServer(handler http.Handler, addr string, cert tls.Certificate) (*Server, error) {
	// handlerListener does the heavy lifting for us, connecting the TCP-level logic with the HTTP
	// request contexts.
	hl, err := newHandlerListener(addr, handler)
	if err != nil {
		return nil, err
	}

	return &Server{
		http.Server{
			Handler: hl,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				// We disable session ticket support to prevent browsers from sending the pre-shared
				// key extension; this extension is not supported by utls.FingerprintClientHello.
				SessionTicketsDisabled: true,
			},
		},
		hl,
	}, nil
}

// Addr returns the network address this server listens on. Until ListenAndServe is called, behavior
// is undefined for incoming connections to this address.
func (s *Server) Addr() net.Addr {
	return s.hl.Addr()
}

// ListenAndServe listens for incoming TCP connections and serves using the handler provided to
// NewServer.
func (s *Server) ListenAndServe() error {
	return s.s.ServeTLS(s.hl, "", "")
}

// Close immediately closes the server, the underlying listener, and any outstanding connections.
func (s *Server) Close() error {
	s.hl.Close()
	return s.s.Close()
}
