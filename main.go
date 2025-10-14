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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/Viespirkiu-grupe/goviesdezeproxy/ziputil"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

type ProxyInfo struct {
	FileURL       string            `json:"fileUrl"`
	Extension     string            `json:"extension"`
	Headers       map[string]string `json:"headers"`
	ContentType   string            `json:"contentType"`
	ContentLength int               `json:"contentLength"`
	FileName      string            `json:"fileName"`
}

var nonAlnumRe = regexp.MustCompile(`[^a-z0-9\.\-_]+`)

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
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)

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
			log.Printf("info json decode error: %v", err)
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

		//Pass-through only safe request headers from info.Headers
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

		// Write status before body to avoid implicit 200
		w.WriteHeader(upRes.StatusCode)
		w.Header().Set("Content-Type", info.ContentType)

		io.Copy(w, upRes.Body)
	}

	handlerPdf := func(w http.ResponseWriter, r *http.Request) {
		// Build requestedId from path params
		id := chi.URLParam(r, "id")
		dokId := chi.URLParam(r, "dokId")
		fileId := chi.URLParam(r, "fileId")
		file := chi.URLParam(r, "*")

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

		if file == "" {
			http.Error(w, "file must end with .pdf", http.StatusBadRequest)
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
			log.Printf("info json decode error: %v", err)
			http.Error(w, "invalid proxy info json", http.StatusBadGateway)
			return
		}
		if info.FileURL == "" {
			http.Error(w, "proxy info missing fileUrl", http.StatusBadGateway)
			return
		}

		pdfURL := info.FileURL
		if strings.Contains(pdfURL, "?") {
			pdfURL += "&format=pdf"
		} else {
			pdfURL += "?format=pdf"
		}

		// Step 2: Request actual file (streaming, no buffering)
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, pdfURL, nil)
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

		if disp := upRes.Header.Get("Content-Disposition"); disp != "" && info.FileName == "" {
			w.Header().Set("Content-Disposition", disp)
		}
		if info.FileName != "" {
			// inline; filename*=UTF-8''... covers unicode safely
			fnStar := filepath.Base(url.PathEscape(file))
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

		buf, err := io.ReadAll(upRes.Body)
		if err != nil {
			log.Printf("reading upstream body error: %v", err)
			http.Error(w, "error reading upstream body", http.StatusBadGateway)
			return
		}

		if req.URL.Query().Has("list") {
			files, err := ziputil.ListFilesInArchive(buf)
			if err != nil {
				log.Printf("ListFilesInArchive error: %v", err)
				http.Error(w, "error listing files in archive: "+err.Error(), http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(files); err != nil {
				log.Printf("writing response body error: %v", err)
				// cannot write http.Error here as headers and status are already sent
				return
			}
			return
		}
		files, err := ziputil.ListFilesInArchive(buf)
		if err != nil {
			log.Printf("ListFilesInArchive error: %v", err)
			http.Error(w, "error listing files in archive: "+err.Error(), http.StatusBadGateway)
			return
		}
		var bestMatch string
		bestSim := 0.0
		for _, f := range files {
			sim := similarity(f, file)
			if sim > bestSim {
				bestSim = sim
				bestMatch = f
			}
		}
		if bestSim < 0.4 {
			http.Error(w, "file not found in archive", http.StatusNotFound)
			return
		}

		rdr, err := ziputil.GetFileFromArchive(buf, bestMatch)
		if err != nil {
			log.Printf("GetFileFromArchive error: %v", err)
			http.Error(w, "error extracting pdf from archive: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer rdr.Close()

		// Write status before body to avoid implicit 200
		w.WriteHeader(upRes.StatusCode)
		_, err = io.Copy(w, rdr)
		if err != nil {
			log.Printf("writing response body error: %v", err)
			// cannot write http.Error here as headers and status are already sent
			return
		}
	}

	r.Get("/{id:[0-9]+}", handler)
	r.Get("/{dokId:[0-9]+}/{fileId:[0-9]+}", handler)
	r.Get("/{id:[0-9]+}/*", handlerPdf)
	r.Get("/{dokId:[0-9]+}/{fileId:[0-9]+}/*", handlerPdf)

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

func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			ins := cur[j-1] + 1
			del := prev[j] + 1
			sub := prev[j-1] + cost
			// min
			min := ins
			if del < min {
				min = del
			}
			if sub < min {
				min = sub
			}
			cur[j] = min
		}
		copy(prev, cur)
	}
	return cur[lb]
}

func normalize(s string) string {
	s = strings.ToLower(s)
	t := norm.NFKD.String(s)
	b := make([]rune, 0, len(t))
	for _, r := range t {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		b = append(b, r)
	}
	out := string(b)
	out = nonAlnumRe.ReplaceAllString(out, "")
	return out
}

func similarity(a, b string) float64 {
	na := normalize(a)
	nb := normalize(b)
	if len(na) == 0 && len(nb) == 0 {
		return 1.0
	}
	dist := levenshtein(na, nb)
	maxLen := len(na)
	if len(nb) > maxLen {
		maxLen = len(nb)
	}
	if maxLen == 0 {
		return 0.0
	}
	return 1.0 - float64(dist)/float64(maxLen)
}
