package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

type ProxyInfo struct {
	FileURL       string            `json:"fileUrl"`
	Headers       map[string]string `json:"headers"`
	ContentType   string            `json:"contentType"`
	ContentLength string            `json:"contentLength"`
	FileName      string            `json:"fileName"`
}

func getenvMust(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s must be set (e.g. in .env)", k)
	}
	return v
}

func main() {
	_ = godotenv.Load() // optional: ignore error

	port := os.Getenv("PROXY_PORT")
	if port == "" {
		port = "4000"
	}
	mainServer := getenvMust("MAIN_SERVER") // e.g. http://localhost:3000
	apiKey := getenvMust("PROXY_API_KEY")   // same as DB
	baseURL, err := url.Parse(mainServer)
	if err != nil {
		log.Fatalf("invalid MAIN_SERVER: %v", err)
	}

	// HTTP client for both info and file requests
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   0, // no global timeout; rely on request context
	}

	r := chi.NewRouter()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// Build requestedId from path params
		id := chi.URLParam(r, "id")
		dokId := chi.URLParam(r, "dokId")
		fileId := chi.URLParam(r, "fileId")

		var requestedID string
		switch {
		case dokId != "" && fileId != "":
			// mirror Number() coercion from Node: drop non-digits safely
			if _, err := strconv.Atoi(dokId); err != nil {
				http.Error(w, "dokId must be a number", http.StatusBadRequest)
				return
			}
			if _, err := strconv.Atoi(fileId); err != nil {
				http.Error(w, "fileId must be a number", http.StatusBadRequest)
				return
			}
			requestedID = dokId + "/" + fileId
		case id != "":
			if _, err := strconv.Atoi(id); err != nil {
				http.Error(w, "id must be a number", http.StatusBadRequest)
				return
			}
			requestedID = id
		default:
			http.NotFound(w, r)
			return
		}

		// Step 1: Ask main server for proxy info
		infoURL := *baseURL
		infoURL.Path = strings.TrimRight(baseURL.Path, "/") + "/failas/" + requestedID + "/downloadProxyInformation"

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, infoURL.String(), nil)
		if err != nil {
			http.Error(w, "failed to build request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)

		infoRes, err := client.Do(req)
		if err != nil {
			// could be context cancellation if client disconnected
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			log.Printf("info request error: %v", err)
			http.Error(w, "failed to fetch proxy info", http.StatusBadGateway)
			return
		}
		defer infoRes.Body.Close()

		if infoRes.StatusCode < 200 || infoRes.StatusCode >= 300 {
			w.WriteHeader(infoRes.StatusCode)
			_, _ = io.Copy(w, infoRes.Body)
			return
		}

		var info ProxyInfo
		if err := json.NewDecoder(infoRes.Body).Decode(&info); err != nil {
			http.Error(w, "invalid proxy info json", http.StatusBadGateway)
			return
		}
		if info.FileURL == "" {
			http.Error(w, "proxy info missing fileUrl", http.StatusBadGateway)
			return
		}

		// Step 2: Request actual file (streaming, no buffering)
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, info.FileURL, nil)
		if err != nil {
			http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
			return
		}
		// Pass-through only safe request headers from info.Headers
		for k, v := range info.Headers {
			// skip hop-by-hop / unsafe headers just in case
			kk := strings.ToLower(k)
			switch kk {
			case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailer":
				continue
			default:
				upReq.Header.Set(k, v)
			}
		}

		upRes, err := client.Do(upReq)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			log.Printf("file request error: %v", err)
			http.Error(w, "failed to fetch file", http.StatusBadGateway)
			return
		}
		defer upRes.Body.Close()

		if upRes.StatusCode < 200 || upRes.StatusCode >= 300 {
			w.WriteHeader(upRes.StatusCode)
			_, _ = io.Copy(w, upRes.Body)
			return
		}

		// Step 3: Forward headers
		if info.ContentType != "" {
			w.Header().Set("Content-Type", info.ContentType)
		} else if ct := upRes.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if info.ContentLength != "" {
			w.Header().Set("Content-Length", info.ContentLength)
		} else if cl := upRes.Header.Get("Content-Length"); cl != "" {
			w.Header().Set("Content-Length", cl)
		}
		if disp := upRes.Header.Get("Content-Disposition"); disp != "" && info.FileName == "" {
			w.Header().Set("Content-Disposition", disp)
		}
		if info.FileName != "" {
			// inline; filename*=UTF-8''... covers unicode safely
			fnStar := url.PathEscape(info.FileName)
			w.Header().Set("Content-Disposition",
				fmt.Sprintf("inline; filename*=UTF-8''%s", fnStar))
		}

		// Also forward byte ranges if upstream provided
		if rng := upRes.Header.Get("Accept-Ranges"); rng != "" {
			w.Header().Set("Accept-Ranges", rng)
		}
		if cr := upRes.Header.Get("Content-Range"); cr != "" {
			w.Header().Set("Content-Range", cr)
		}

		// Step 4: Stream body directly
		// Flush-capable?
		flusher, _ := w.(http.Flusher)

		// Write status before body to avoid implicit 200
		w.WriteHeader(upRes.StatusCode)

		buf := make([]byte, 32*1024)
		for {
			// if client disconnected, r.Context().Done() will cancel upReq and io.Copy will fail
			select {
			case <-r.Context().Done():
				return
			default:
			}
			n, readErr := upRes.Body.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					return // client gone
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					return
				}
				// propagate upstream read error as connection close
				log.Printf("stream read error: %v", readErr)
				return
			}
		}
	}

	r.Get("/{id}", handler)
	r.Get("/{dokId}/{fileId}", handler)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadHeaderTimeout: 15 * time.Second,
	}

	// Graceful shutdown
	go func() {
		log.Printf("Proxy server listening on port %s", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Println("bye.")
}
