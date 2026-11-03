// Package web embeds the browser collector UI and vendored libraries.
package web

import "embed"

// FS holds the static web assets under "static/".
//
//go:embed static
var FS embed.FS
