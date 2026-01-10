package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
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
	FileURL            string            `json:"fileUrl"`
	Extension          string            `json:"extension"`
	ContainerExtension string            `json:"containerExtension"`
	Extract            string            `json:"extract"`
	Headers            map[string]string `json:"headers"`
	ContentType        string            `json:"contentType"`
	ContentLength      int               `json:"contentLength"`
	FileName           string            `json:"fileName"`
}

func getenvMust(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s must be set (e.g. in .env)", k)
	}
	return v
}

func cleanTmp() {
	for {
		cmd := exec.Command("find", "/tmp", "-mindepth", "1", "-mmin", "+5", "-exec", "rm", "-rf", "{}", "+")
		if err := cmd.Run(); err != nil {
			log.Println("Error running find:", err)
		}
		time.Sleep(1 * time.Minute)
	}
}

func main() {
	go cleanTmp() // runs in background

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

	handlerArchive := func(w http.ResponseWriter, r *http.Request) {
		// -------- Resolve requestedID --------
		id := chi.URLParam(r, "id")
		dokId := chi.URLParam(r, "dokId")
		fileId := chi.URLParam(r, "fileId")
		pathFile := chi.URLParam(r, "*")

		var requestedID string
		switch {
		case dokId != "" && fileId != "":
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
			if !regexp.MustCompile(`^\d+$|^[a-fA-F0-9]{32}$`).MatchString(id) {
				http.Error(w, "id must be a number or MD5", http.StatusBadRequest)
				return
			}
			requestedID = id
		default:
			http.NotFound(w, r)
			return
		}

		// -------- Fetch proxy info --------
		infoURL := *baseURL
		infoURL.Path = strings.TrimRight(baseURL.Path, "/") +
			"/failas/" + requestedID + "/downloadProxyInformation"

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, infoURL.String(), nil)
		if err != nil {
			http.Error(w, "failed to build request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)

		infoRes, err := client.Do(req)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			http.Error(w, "failed to fetch proxy info", http.StatusBadGateway)
			return
		}
		defer infoRes.Body.Close()

		if infoRes.StatusCode < 200 || infoRes.StatusCode >= 300 {
			w.WriteHeader(infoRes.StatusCode)
			io.Copy(w, infoRes.Body)
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

		// -------- Fetch upstream file --------
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, info.FileURL, nil)
		if err != nil {
			http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
			return
		}

		for k, v := range info.Headers {
			switch strings.ToLower(k) {
			case "connection", "proxy-connection", "keep-alive",
				"transfer-encoding", "upgrade", "te", "trailer":
				continue
			default:
				upReq.Header.Set(k, v)
			}
		}

		upRes, err := client.Do(upReq)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			http.Error(w, "failed to fetch file", http.StatusBadGateway)
			return
		}
		defer upRes.Body.Close()

		if upRes.StatusCode < 200 || upRes.StatusCode >= 300 {
			w.WriteHeader(upRes.StatusCode)
			io.Copy(w, upRes.Body)
			return
		}

		var rdr io.ReadCloser
		var name string

		target := info.Extract
		if target == "" {
			target = pathFile
		}

		if target == "" {
			// No extraction needed, stream raw file
			rdr = upRes.Body
			name = info.FileName
		} else {
			// Extraction required
			buf, err := io.ReadAll(upRes.Body)
			if err != nil {
				http.Error(w, "error reading upstream body", http.StatusBadGateway)
				return
			}

			ext := info.ContainerExtension
			if ext == "" {
				ext = info.Extension
			}

			switch ext {
			case "eml":
				rdr, err = ziputil.ExtractEmlAttachments(buf, target, r.URL.Query().Get("index"))
				if err != nil {
					http.Error(w, "error extracting eml attachment", http.StatusBadGateway)
					return
				}
				name = target

			case "msg":
				eml, err := ziputil.ConvertMsgToEml(buf)
				if err != nil {
					http.Error(w, "error converting msg", http.StatusBadGateway)
					return
				}
				rdr, err = ziputil.ExtractEmlAttachments(eml, target, r.URL.Query().Get("index"))
				if err != nil {
					http.Error(w, "error extracting msg attachment", http.StatusBadGateway)
					return
				}
				name = target

			default: // normal archive (zip/rar/tar)
				files, err := ziputil.IdentityFilesV2(buf)
				if err != nil {
					http.Error(w, "invalid archive", http.StatusBadGateway)
					return
				}

				best, err := bestMatch(target, files)
				if err != nil {
					http.Error(w, "file not found in archive", http.StatusNotFound)
					return
				}

				rdr, err = ziputil.GetFileFromArchiveV2(buf, best)
				if err != nil {
					http.Error(w, "error extracting file", http.StatusBadGateway)
					return
				}
				name = best
			}
		}

		if info.Extract != "" {
			name = info.FileName
		}

		// Always serve the **extracted file**
		if converter(w, r, upRes, rdr, name) {
			return
		}

		writeResponse(w, r, rdr, upRes, name)
	}

	r.Get("/{dokId:[0-9]+}/{fileId:[0-9]+}", handlerArchive)
	r.Get("/{dokId:[0-9]+}/{fileId:[0-9]+}/*", handlerArchive)

	r.Get("/{id:[0-9a-fA-F]{32}|[0-9]+}", handlerArchive)
	r.Get("/{id:[0-9a-fA-F]{32}|[0-9]+}/*", handlerArchive)

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
		log.Printf("considering file %q %v %s with similarity %.3f", f, f, f, sim)
		if sim > bestSim || strings.ToLower(f) == strings.ToLower(file) {
			bestSim = sim
			bestMatch = f
		}
	}
	if bestSim < 0.4 {
		return "", errors.New("file not found in archive")
	}
	log.Printf("best match: %q with similarity %.3f", bestMatch, bestSim)
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

func writeResponse(w http.ResponseWriter, r *http.Request, rdr io.ReadCloser, upRes *http.Response, name string) bool {
	defer rdr.Close()

	// Determine content type from extension
	contentType := contentTypeFromExt(name)

	w.Header().Set("Content-Type", contentType)

	// Content-Disposition: inline; filename*=UTF-8''...
	if name != "" {
		nameOnly := path.Base(name) // get the last part of the path
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("inline; filename*=UTF-8''%s", url.PathEscape(nameOnly)))
	}

	// Cache-Control: same as before
	w.Header().Set("Cache-Control", "public, max-age=2592000, immutable")

	// Forward byte ranges if upstream provided (optional)
	if rng := upRes.Header.Get("Accept-Ranges"); rng != "" {
		w.Header().Set("Accept-Ranges", rng)
	}
	if cr := upRes.Header.Get("Content-Range"); cr != "" {
		w.Header().Set("Content-Range", cr)
	}

	// Status code
	w.WriteHeader(upRes.StatusCode)

	// Copy body
	if _, err := io.Copy(w, rdr); err != nil {
		log.Printf("writing response body error: %v", err)
		return true
	}

	return false
}

func contentTypeFromExt(filename string) string {
	ext := filepath.Ext(filename)
	if ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			return ct
		}
	}
	return "application/octet-stream"
}
