// Command specgen provides a utility for generating utls.ClientHelloSpecs. This command starts an
// HTTPS server which responds to every request with a ClientHelloSpec corresponding to the TLS
// ClientHello the server received. The spec is logged for every request as well. Make a request of
// the server via web browser to see a ClientHelloSpec for the browser.
//
// It is recommended that mkcert be used to generate the keypair for this server. This ensures
// browsers do not flag and block the page. See https://github.com/FiloSottile/mkcert.
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/getlantern/utls/specgen"
	"github.com/getlantern/utls/specgen/specgen/hellocap"
)

const certFileDefaultText = "pre-defined, self-signed cert"

var (
	addr          = flag.String("addr", "localhost:0", "address to listen on")
	certFile      = flag.String("cert", certFileDefaultText, "PEM-encoded TLS certificate file")
	keyFile       = flag.String("key", "", "PEM-encoded TLS key file")
	packagePrefix = flag.String("prefix", "", "package prefix; see specgen.WriteHelloSpec")
)

func handleRequest(rw http.ResponseWriter, req *http.Request) {
	hello, err := hellocap.FromRequest(req)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(rw, "error capturing ClientHello")
		log.Println("error capturing ClientHello:", err)
		return
	}

	buf := new(bytes.Buffer)
	err = specgen.WriteHelloSpec(buf, hello, *packagePrefix)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(rw, "error writing ClientHello")
		log.Println("error writing ClientHello:", err)
		return
	}

	ua := req.Header.Get("User-Agent")

	fmt.Fprintln(rw, buf.String())
	log.Printf("captured ClientHello from %s:\n%s\n", ua, buf.String())
}

func main() {
	flag.Parse()

	var cert tls.Certificate
	var err error
	if *certFile == certFileDefaultText {
		cert, err = tls.X509KeyPair([]byte(defaultCertPEM), []byte(defaultKeyPEM))
	} else {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	}
	if err != nil {
		log.Panicf("failed to load cert: %v", err)
	}

	s, err := hellocap.NewServer(http.HandlerFunc(handleRequest), *addr, cert)
	if err != nil {
		log.Panic(err)
	}

	log.Println("Listening for incoming connections on", s.Addr())

	if err := s.ListenAndServe(); err != nil {
		log.Panic(err)
	}
}

// A self-signed TLS key pair valid until 2032.
var (
	defaultCertPEM = `-----BEGIN CERTIFICATE-----
MIICyDCCAjGgAwIBAgIUTAmBa1Dd9Hz0pRjoYzi93d+e9GkwDQYJKoZIhvcNAQEL
BQAwcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYDVQQHDAhTb21lQ2l0
eTESMBAGA1UECgwJTXlDb21wYW55MRMwEQYDVQQLDApNeURpdmlzaW9uMRgwFgYD
VQQDDA93d3cuY29tcGFueS5jb20wHhcNMjIxMTA2MjMyNDEzWhcNMzIxMTAzMjMy
NDEzWjBwMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCFNvbWVD
aXR5MRIwEAYDVQQKDAlNeUNvbXBhbnkxEzARBgNVBAsMCk15RGl2aXNpb24xGDAW
BgNVBAMMD3d3dy5jb21wYW55LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAoWRAcyBPWAOEIBS7vJIdTKvdRGoY811RYTL1b78i68zIU87Hw03oSL2aw1ol
gIcFWjupLA8nUI4I6n2ZXpc3tEmf45NPAQEh1V7kxf03CWimbmPw1DHTypYM/Wps
af9xM+1+jP6ns/h1d8dO4UWdNbMf04+4k0vQtKCshGPniWMCAwEAAaNfMF0wCwYD
VR0PBAQDAgRwMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBoGA1UdEQQTMBGCCWxvY2Fs
aG9zdIcEfwAAATAdBgNVHQ4EFgQUEosohEbGBpAeOSVjgf24dql8JlswDQYJKoZI
hvcNAQELBQADgYEAGywH1HYIL0WaBhLcg5OoYfyWJ20OfTHxLvdMAoM6YVaui1fW
/Lmf+BTWafx0FW/BLd/ZretaQmvBeUnATz6pZX+kMAZ0AY6Ya/usxpJL1re2W3o9
nD7qdzdP4OLtYm5xTWOdZR/oj3lZzHNGZmCjs7P/VML4129my1OWAVfINCw=
-----END CERTIFICATE-----`

	defaultKeyPEM = `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKFkQHMgT1gDhCAU
u7ySHUyr3URqGPNdUWEy9W+/IuvMyFPOx8NN6Ei9msNaJYCHBVo7qSwPJ1COCOp9
mV6XN7RJn+OTTwEBIdVe5MX9Nwlopm5j8NQx08qWDP1qbGn/cTPtfoz+p7P4dXfH
TuFFnTWzH9OPuJNL0LSgrIRj54ljAgMBAAECgYBHqWgktngEsKr+Q7aIqKhx3u5E
7oddqFX2PtZUZB5xbWCWNf7lbbZydh4+F80HIOzzgAJCGghu8GJtHI/5PFPy+ORH
XZvU7eTqt35LM5uuSLisrD/laOPVnCPGrLfmX8U+d00ffwLsiNJ69bCAooia2gzA
zMVOU9STzQVUdN8sIQJBANbY/vTK8uXDKlmA//eHzvuC5axa+Gmbz8a3z250rs17
SXUZdIVauwyFWIoaCbZJCd7ow6WSy9WpasZKciXAYUcCQQDATg0+8xbakhLlN9V9
FzHxNlkQJq6OrHfxNSIEANppI+xmoMlnKDQuoTrubEeKLienPzxzVLqtjPPoTthW
ZsUFAkAk+Oa3HY27OGC7UlW6NSbLZXU8udLx6ZxR6CPMMEw8lDDJ8/13TWvO9cuM
yHpPYjZOo+O3RJHLTQJQ6VLHaFnVAkEAs5xy/LeZQd4rLdIfYS135P5I4y/t2640
fKKOucR+OrNlylkko2fGjULjwup5SxNez/PdJy8dCJnc+b4ii1iDbQJBAKNhQf+H
s0gTmodJUZ9+7hF6c8D7js2UTc2r79D34nRE3yXmZDU2dJHT2KXbizBPET3OXmtN
GGAzrM+tNzEmHDc=
-----END PRIVATE KEY-----`
)
