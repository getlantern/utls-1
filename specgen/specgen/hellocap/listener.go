package hellocap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
)

const tlsRecordHeaderLen = 5

type contextKey int

// contextHelloKey is the context key for retrieving the ClientHello.
const contextHelloKey contextKey = 0

// FromRequest returns the TLS ClientHello sent by the remote. This request must have come through a
// handler attached to the Server type in this package.
func FromRequest(req *http.Request) ([]byte, error) {
	hello, ok := req.Context().Value(contextHelloKey).(capturedHello)
	if !ok {
		return nil, errors.New("no attached ClientHello")
	}
	return hello.hello, hello.err
}

// attachHello is used to put a captured ClientHello on a http.Request context. This is how the
// ClientHello, captured at the TCP level, is made available to users of this library.
func attachHello(req *http.Request, hello capturedHello) *http.Request {
	ctx := context.WithValue(req.Context(), contextHelloKey, hello)
	return req.Clone(ctx)
}

// onHello is a callback invoked when a ClientHello is captured. Only one of hello or err will be
// non-nil. This callback is not invoked for incomplete ClientHellos. In other words, err is non-nil
// only if what has been read off the connection could not possibly constitute a ClientHello,
// regardless of further data from the connection.
type onHello func(hello []byte, err error)

// capturingConn is a TCP connection and implements net.Conn. If a TLS ClientHello is sent by the
// peer, capturingConn will invoke the provided onHello callback. This is the basic building block
// by which we build a hello-capturing server.
type capturingConn struct {
	// Wraps a TCP connection.
	net.Conn

	helloRead bool
	helloBuf  *bytes.Buffer
	helloLock sync.Mutex // protects fields in this block

	onHello onHello
	onClose func()
}

func newCapturingConn(wrapped net.Conn, onHello onHello, onClose func()) *capturingConn {
	return &capturingConn{
		wrapped,
		false,
		new(bytes.Buffer),
		sync.Mutex{},
		onHello,
		onClose,
	}
}

func (c *capturingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	c.checkHello(b[:n])
	return
}

func (c *capturingConn) checkHello(newBytes []byte) {
	c.helloLock.Lock()
	if !c.helloRead {
		c.helloBuf.Write(newBytes)
		if c.helloBuf.Len() >= tlsRecordHeaderLen {
			helloLen, err := parseClientHelloHeader(c.helloBuf.Bytes()[:tlsRecordHeaderLen])
			if err != nil {
				c.onHello(nil, fmt.Errorf("failed to parse header: %w", err))
				c.helloRead = true
			}
			if c.helloBuf.Len() >= helloLen {
				c.onHello(c.helloBuf.Bytes()[:helloLen+tlsRecordHeaderLen], nil)
				c.helloRead = true
			}
		}
	}
	c.helloLock.Unlock()
}

func (c *capturingConn) Close() error {
	c.onClose()
	return c.Conn.Close()
}

type capturedHello struct {
	hello []byte
	err   error
}

// handlerListener is used to listen for raw TCP connections as part of an HTTPS server. The TCP
// connections are assumed to come from TLS clients. handlerListener captures the TLS ClientHello
// (using capturingConn) and attaches it to the *http.Request context (using attachHello).
//
// Implements net.Listener and http.Handler.
type handlerListener struct {
	tcpListener net.Listener
	handler     http.Handler

	hellosByRemote map[string]capturedHello
	sync.Mutex
}

func newHandlerListener(addr string, handler http.Handler) (*handlerListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &handlerListener{
		l, handler, map[string]capturedHello{}, sync.Mutex{},
	}, nil
}

func (hl *handlerListener) Addr() net.Addr {
	return hl.tcpListener.Addr()
}

func (hl *handlerListener) Accept() (net.Conn, error) {
	conn, err := hl.tcpListener.Accept()
	if err != nil {
		return nil, err
	}

	onHello := func(hello []byte, err error) {
		hl.Lock()
		hl.hellosByRemote[conn.RemoteAddr().String()] = capturedHello{hello, err}
		hl.Unlock()
	}
	onClose := func() {
		hl.Lock()
		delete(hl.hellosByRemote, conn.RemoteAddr().String())
		hl.Unlock()
	}

	return newCapturingConn(conn, onHello, onClose), nil
}

func (hl *handlerListener) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	hl.Lock()
	hello, ok := hl.hellosByRemote[req.RemoteAddr]
	hl.Unlock()

	if ok {
		req = attachHello(req, hello)
	}
	hl.handler.ServeHTTP(rw, req)
}

func (hl *handlerListener) Close() error {
	return hl.tcpListener.Close()
}

func parseClientHelloHeader(hdr []byte) (recordLen int, err error) {
	const (
		recordTypeChangeCipherSpec = 0x14
		recordTypeAlert            = 0x15
		recordTypeHandshake        = 0x16
		recordTypeApplicationData  = 0x17

		versionSSL30 = 0x0300
		versionTLS13 = 0x0304
	)

	if len(hdr) < tlsRecordHeaderLen {
		return 0, fmt.Errorf("header must be at least %d bytes", tlsRecordHeaderLen)
	}

	// Ensure this is a handshake record. Provide a specific error message when possible.
	if hdr[0] == recordTypeAlert {
		// n.b. We're unlikely to get a CCS or application data record out of order.
		return 0, errors.New("bad record type, received alert record")
	}
	if hdr[0] < recordTypeChangeCipherSpec || hdr[0] > recordTypeApplicationData {
		return 0, errors.New("not a TLS record")
	}
	if hdr[0] != recordTypeHandshake {
		return 0, fmt.Errorf("bad record type: %#x", hdr[0])
	}

	version := uint16(hdr[1])<<8 | uint16(hdr[2])
	if version < versionSSL30 || version > versionTLS13 {
		return 0, fmt.Errorf("bad version: %#x", version)
	}

	len := int(hdr[3])<<8 | int(hdr[4])
	return len, nil
}
