package hellocap_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/getlantern/utls/specgen/specgen/hellocap"
)

func handler(w http.ResponseWriter, req *http.Request) {
	hello, err := hellocap.FromRequest(req)
	if err != nil {
		log.Printf("error capturing hello: %v", err)
		return
	}

	// Respond to the client with their own captured ClientHello.
	fmt.Fprintf(w, "%#x\n", hello)
}

func Example() {
	serverCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		log.Panic(err)
	}

	s, err := hellocap.NewServer(http.HandlerFunc(handler), "localhost:0", serverCert)
	if err != nil {
		log.Panic(err)
	}
	defer s.Close()

	go s.ListenAndServe()

	c := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := c.Get("https://" + s.Addr().String())
	if err != nil {
		log.Panic(err)
	}
	defer resp.Body.Close()

	echoedHello, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}

	// Print the first 3 bytes of the record header.
	// (This will be 8 characters: the 2-byte prefix + 3 * 2 characters per byte).
	fmt.Println(string(echoedHello)[:8])

	// Output: 0x160301
}

// A self-signed TLS key pair valid until 2032.
var (
	certPEM = `-----BEGIN CERTIFICATE-----
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

	keyPEM = `-----BEGIN PRIVATE KEY-----
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
