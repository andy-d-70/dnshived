// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "net/http"

// faviconSVG is a byte-for-byte copy of artwork/favicon.svg (the project's
// canonical design source).
const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<style>
  .nd { fill: #1F2937; }
  .ring-dim { stroke: #D1D5DB; }
  .auth { stroke: #0D9488; }
  @media (prefers-color-scheme: dark) {
    .nd { fill: #D1D5DB; }
    .ring-dim { stroke: #4B5563; }
    .auth { stroke: #14B8A6; }
  }
</style>
<path d="M 16 46 A 24 24 0 0 1 32 10" fill="none" class="ring-dim" stroke-width="4" stroke-linecap="round"/>
<path d="M 48 46 A 24 24 0 0 1 16 46" fill="none" class="ring-dim" stroke-width="4" stroke-linecap="round"/>
<path d="M 32 10 A 24 24 0 0 1 48 46" fill="none" class="auth" stroke-width="5" stroke-linecap="round"/>
<circle cx="32" cy="10" r="6" class="nd" stroke="none"/>
<circle cx="16" cy="46" r="6" class="nd" stroke="none"/>
<circle cx="48" cy="46" r="6" class="nd" stroke="none"/>
</svg>
`

// handleFavicon serves the SVG favicon at both conventional paths.
func handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write([]byte(faviconSVG))
}
