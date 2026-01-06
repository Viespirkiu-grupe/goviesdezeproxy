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

	"github.com/Viespirkiu-grupe/goviesdezeproxy/utils"
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
			matchedNumber := regexp.MustCompile(`^\d+$`).MatchString(id)
			matchedMD5 := regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(id)
			if !matchedNumber && !matchedMD5 {
				http.Error(w, "id must be a number or MD5", http.StatusBadRequest)
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

		convertTo := strings.ToLower(r.URL.Query().Get("convertTo"))
		origExt := strings.ToLower(info.Extension)

		isImage := map[string]bool{
			"jpg": true, "jpeg": true, "png": true, "tif": true, "tiff": true,
			"bmp": true, "prn": true, "gif": true, "jfif": true, "heic": true,
			"avif": true, "webp": true,
		}

		switch convertTo {
		case "pdf":
			// If original is already an image, use image→PDF
			if isImage[origExt] {
				if err := utils.ConvertImageReaderToPDF(
					w,
					r,
					upRes.Body,
					info.FileName,
					upRes.StatusCode,
				); err != nil {
					log.Printf("image→pdf conversion error: %v", err)
					http.Error(w, "conversion failed", http.StatusInternalServerError)
				}
				return
			}

			// Otherwise use document→PDF
			if err := utils.ConvertDocumentReaderToPDF(
				w,
				r,
				upRes.Body,
				info.FileName,
				upRes.StatusCode,
			); err != nil {
				log.Printf("pdf conversion error: %v", err)
				http.Error(w, "conversion failed", http.StatusInternalServerError)
			}
			return

		case "jpg", "jpeg", "png", "tif", "tiff", "bmp", "prn", "gif", "jfif", "heic", "avif", "webp":
			out, err := utils.ConvertImageReader(upRes.Body, convertTo)
			if err != nil {
				log.Printf("image conversion error: %v", err)
				http.Error(w, "conversion failed", http.StatusInternalServerError)
				return
			}
			defer out.Close()
			// w eina i browseri .
			w.Header().Set("Content-Type", "image/"+convertTo)
			if info.FileName != "" {
				fn := strings.TrimSuffix(info.FileName, filepath.Ext(info.FileName)) + "." + convertTo
				w.Header().Set(
					"Content-Disposition",
					fmt.Sprintf("inline; filename*=UTF-8''%s", url.PathEscape(fn)),
				)
			}
			w.WriteHeader(upRes.StatusCode)
			if _, err := io.Copy(w, out); err != nil {
				log.Printf("writing converted image failed: %v", err)
			}
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
		w.Header().Set("Content-Type", info.ContentType)

		// Cache-Control "public, max-age=2592000, immutable" always;
		w.Header().Set("Cache-Control", "public, max-age=2592000, immutable")
		w.WriteHeader(upRes.StatusCode)

		io.Copy(w, upRes.Body)
	}

	handlerArchive := func(w http.ResponseWriter, r *http.Request) {
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
			matchedNumber := regexp.MustCompile(`^\d+$`).MatchString(id)
			matchedMD5 := regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(id)
			if !matchedNumber && !matchedMD5 {
				http.Error(w, "id must be a number or MD5", http.StatusBadRequest)
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

		fileURL := info.FileURL

		// Step 2: Request actual file (streaming, no buffering)
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, fileURL, nil)
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
		if info.Extension != "eml" && info.Extension != "msg" {

			var files []string
			files, err = ziputil.IdentityFilesV2(buf)
			if err != nil {
				log.Printf("ListFilesInArchive error: %v", err)
				http.Error(w, "error listing files in archive: "+err.Error(), http.StatusBadGateway)
				return
			}
			log.Printf("Files from archive: %+v", files)
			bestMatch, err := bestMatch(file, files)
			if err != nil {
				http.Error(w, "file not found in archive", http.StatusNotFound)
				return
			}
			log.Printf("Best match: %+v", bestMatch)
			rdr, err := ziputil.GetFileFromArchiveV2(buf, bestMatch)
			if err != nil {
				if err != nil {
					log.Printf("GetFileFromRarArchive error: %v %v", err, bestMatch)
					http.Error(w, "error extracting file from archive", http.StatusBadGateway)
					return
				}
			}
			defer rdr.Close()

			if converter(w, r, upRes, rdr, bestMatch) == true {
				return
			}

			if writeResponse(w, r, rdr, upRes) == true {
				return
			}
		} else if info.Extension == "eml" {
			rdr, err := ziputil.ExtractEmlAttachments(buf, file, r.URL.Query().Get("index"))
			if err != nil {
				log.Printf("ExtractEmlAttachments error: %v %v", err, file)
				http.Error(w, "error extracting file from eml", http.StatusBadGateway)
				return
			}
			defer rdr.Close()

			writeResponse(w, r, rdr, upRes)
		} else if info.Extension == "msg" {
			eml, err := ziputil.ConvertMsgToEml(buf)
			if err != nil {
				log.Printf("ConvertMsgToEml error: %v", err)
				http.Error(w, "error converting msg to eml", http.StatusBadGateway)
				return
			}

			rdr, err := ziputil.ExtractEmlAttachments(eml, file, r.URL.Query().Get("index"))
			if err != nil {
				log.Printf("ExtractMsgAttachments error: %v %v", err, file)
				http.Error(w, "error extracting file from msg", http.StatusBadGateway)
				return
			}
			defer rdr.Close()
			writeResponse(w, r, rdr, upRes)
		}

	}

	r.Get("/{dokId:[0-9]+}/{fileId:[0-9]+}/*", handlerArchive)
	r.Get("/{id:[0-9a-fA-F]{32}|[0-9]+}/*", handlerArchive)

	r.Get("/{dokId:[0-9]+}/{fileId:[0-9]+}", handler)
	r.Get("/{id:[0-9a-fA-F]{32}|[0-9]+}", handler)

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

func bestMatch(file string, files []string) (string, error) {
	var bestMatch string
	bestSim := 0.0
	for _, f := range files {
		sim := utils.Similarity(f, file)
		if sim > bestSim {
			bestSim = sim
			bestMatch = f
			log.Printf("considering file %q %v %s with similarity %.3f", f, f, f, sim)
		}
	}
	if bestSim < 0.4 {
		return "", errors.New("file not found in archive")
	}
	return bestMatch, nil
}

func converter(
	w http.ResponseWriter,
	r *http.Request,
	upRes *http.Response,
	rdr io.ReadCloser,
	bestMatch string,
) bool {
	convertTo := strings.ToLower(r.URL.Query().Get("convertTo"))
	origExt := strings.ToLower(strings.TrimPrefix(filepath.Ext(bestMatch), "."))

	isImage := map[string]bool{
		"jpg": true, "jpeg": true, "png": true, "tif": true, "tiff": true,
		"bmp": true, "prn": true, "gif": true, "jfif": true, "heic": true,
	}

	switch convertTo {
	case "pdf":
		if isImage[origExt] {
			if err := utils.ConvertImageReaderToPDF(
				w,
				r,
				rdr,
				bestMatch,
				upRes.StatusCode,
			); err != nil {
				log.Printf("archive image→pdf conversion error: %v", err)
				http.Error(w, "conversion failed", http.StatusInternalServerError)
			}
			return true
		}

		if err := utils.ConvertDocumentReaderToPDF(
			w,
			r,
			rdr,
			bestMatch,
			upRes.StatusCode,
		); err != nil {
			log.Printf("archive document→pdf conversion error: %v", err)
			http.Error(w, "conversion failed", http.StatusInternalServerError)
		}
		return true

	case "jpg", "jpeg", "png", "tif", "tiff", "bmp", "prn", "gif", "jfif", "heic":
		// Only images can be converted to images
		if !isImage[origExt] {
			http.Error(w, "source file is not an image", http.StatusBadRequest)
			return true
		}

		out, err := utils.ConvertImageReader(rdr, convertTo)
		if err != nil {
			log.Printf("archive image→image conversion error: %v", err)
			http.Error(w, "conversion failed", http.StatusInternalServerError)
			return true
		}
		defer out.Close()

		w.Header().Set("Content-Type", "image/"+convertTo)
		fn := strings.TrimSuffix(bestMatch, filepath.Ext(bestMatch)) + "." + convertTo
		w.Header().Set(
			"Content-Disposition",
			fmt.Sprintf("inline; filename*=UTF-8''%s", url.PathEscape(fn)),
		)
		w.WriteHeader(upRes.StatusCode)

		if _, err := io.Copy(w, out); err != nil {
			log.Printf("writing converted image failed: %v", err)
		}
		return true
	}
	return false
}

func writeResponse(w http.ResponseWriter, r *http.Request, rdr io.ReadCloser, upRes *http.Response) bool {
	// Write status before body to avoid implicit 200

	w.Header().Set("Cache-Control", "public, max-age=2592000, immutable")
	w.WriteHeader(upRes.StatusCode)
	_, err := io.Copy(w, rdr)
	if err != nil {
		log.Printf("writing response body error: %v", err)
		// cannot write http.Error here as headers and status are already sent
		return true
	}
	return false
}
