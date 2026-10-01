// Package web contains the embedded operator console.
package web

import "embed"

//go:embed static
var Static embed.FS
