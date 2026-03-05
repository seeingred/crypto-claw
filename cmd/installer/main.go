package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
)

//go:embed all:ui/dist
var uiFS embed.FS

func main() {
	port := flag.Int("port", 3000, "HTTP server port")
	noBrowser := flag.Bool("no-browser", false, "skip auto-opening browser")
	flag.Parse()

	slog.Info("Crypto Claw Installer", "port", *port)

	state := &WizardState{
		Step: "welcome",
	}

	mux := http.NewServeMux()

	// Register API routes.
	registerAPIRoutes(mux, state)

	// Serve embedded frontend.
	mux.Handle("/", frontendHandler())

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	url := fmt.Sprintf("http://%s", addr)

	if !*noBrowser {
		go openBrowser(url)
	}

	slog.Info("installer wizard running", "url", url)
	fmt.Printf("\n  Crypto Claw Installer\n  %s\n\n", url)

	server := &http.Server{
		Addr:    addr,
		Handler: corsMiddleware(mux),
	}

	if err := server.ListenAndServe(); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// frontendHandler returns an http.Handler that serves the embedded Svelte UI.
// If the UI has not been built (the embed directory is empty), it serves a
// fallback message.
func frontendHandler() http.Handler {
	sub, err := fs.Sub(uiFS, "ui/dist")
	if err != nil {
		slog.Warn("embedded UI not available, serving fallback", "error", err)
		return http.HandlerFunc(fallbackHandler)
	}

	// Check if the dist directory actually has an index.html (i.e., the UI was built).
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return http.HandlerFunc(fallbackHandler)
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the requested file; if it doesn't exist, serve index.html
		// to support SPA client-side routing.
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Check if the file exists in the embedded FS.
		f, err := sub.Open(path[1:]) // strip leading /
		if err != nil {
			// File not found - serve index.html for SPA routing.
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		f.Close()
		fileServer.ServeHTTP(w, r)
	})
}

// fallbackHandler serves a minimal HTML page when the Svelte UI hasn't been built.
func fallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Crypto Claw Installer</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; padding: 0 20px; color: #333; }
    h1 { color: #1a1a2e; }
    code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
    pre { background: #f0f0f0; padding: 16px; border-radius: 6px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>Crypto Claw Installer</h1>
  <p>The web UI has not been built yet. To build it:</p>
  <pre>cd web/installer
npm install
npm run build</pre>
  <p>Then restart the installer.</p>
  <hr>
  <p>The API is available at <code>/api/state</code>. You can use the REST API directly.</p>
</body>
</html>`)
}

// corsMiddleware adds CORS headers for local development.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// openBrowser opens the default browser to the given URL.
func openBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		slog.Info("open this URL in your browser", "url", url)
		return
	}

	if err := cmd.Start(); err != nil {
		slog.Warn("could not open browser", "error", err, "url", url)
	}
}
