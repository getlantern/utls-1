module github.com/getlantern/utls

go 1.18

require (
	github.com/andybalholm/brotli v1.0.4
	github.com/klauspost/compress v1.13.6
	// The upstream appears here because import paths have not been renamed (we expect consumers to
	// include a replace directive in their go.mod file). Its presence here does not seem to have
	// any effect.
	github.com/refraction-networking/utls v1.0.0
	golang.org/x/crypto v0.1.0
	golang.org/x/net v0.1.0
)

require (
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/text v0.4.0 // indirect
)
