// Package e2e holds live end-to-end tests that query the real OTX API. They
// are guarded by the `e2e` build tag so `go test ./...` (offline) never runs
// them; run them deliberately with:
//
//	make e2e          # or: go test -tags e2e -count=1 ./e2e/...
//
// Fixtures have to be chosen for stability, not for drama: an indicator with
// long-standing pulses, a clean indicator with none, and one carrying a
// false-positive flag. Pulses are community submissions and can be edited or
// deleted, so a fixture picked because it looked interesting today is a test
// that fails next month for no reason of ours.
//
// This file has no build tag so the package always compiles (and reports "no
// test files" without the tag).
package e2e
