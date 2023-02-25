module github.com/getlantern/utls

go 1.18

require (
	github.com/andybalholm/brotli v1.0.4
	github.com/klauspost/compress v1.13.6
	// The upstream appears here because import paths have not been renamed (we expect consumers to
	// include a replace directive in their go.mod file). Its presence here does not seem to have
	// any effect.
	github.com/refraction-networking/utls v1.0.0
	golang.org/x/crypto v0.0.0-20211108221036-ceb1ce70b4fa
	golang.org/x/net v0.0.0-20211111160137-58aab5ef257a
)

require (
	golang.org/x/sys v0.1.0 // indirect
	golang.org/x/text v0.3.6 // indirect
)
