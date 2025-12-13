package utils

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ConvertDocumentReaderToPDF(
	w http.ResponseWriter,
	r *http.Request,
	src io.Reader,
	origName string,
	status int,
) error {
	tmpIn, err := os.CreateTemp("", "archive-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpIn.Name())

	if _, err := io.Copy(tmpIn, src); err != nil {
		tmpIn.Close()
		return err
	}
	tmpIn.Close()

	outDir := os.TempDir()
	cmd := exec.Command(
		"libreoffice",
		"--headless",
		"--convert-to", "pdf",
		"--outdir", outDir,
		tmpIn.Name(),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("libreoffice failed: %w: %s", err, output)
	}

	pdfPath := filepath.Join(
		outDir,
		strings.TrimSuffix(filepath.Base(tmpIn.Name()), filepath.Ext(tmpIn.Name()))+".pdf",
	)
	defer os.Remove(pdfPath)

	f, err := os.Open(pdfPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if origName != "" {
		fn := url.PathEscape(strings.TrimSuffix(origName, filepath.Ext(origName)))
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("inline; filename*=UTF-8''%s.pdf", fn))
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Cache-Control", "public, max-age=2592000, immutable")
	w.WriteHeader(status)
	_, err = io.Copy(w, f)
	return err
}

// ConvertImageReaderToPDF converts an image reader into a PDF and streams it to w
func ConvertImageReaderToPDF(
	w http.ResponseWriter,
	r *http.Request,
	src io.Reader,
	origName string,
	status int,
) error {
	// Save the image to a temp file
	tmpIn, err := os.CreateTemp("", "image-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmpIn.Name())

	if _, err := io.Copy(tmpIn, src); err != nil {
		tmpIn.Close()
		return err
	}
	tmpIn.Close()

	// Prepare output PDF path
	tmpOutDir := os.TempDir()
	baseName := strings.TrimSuffix(filepath.Base(tmpIn.Name()), filepath.Ext(tmpIn.Name()))
	pdfPath := filepath.Join(tmpOutDir, baseName+".pdf")

	// Convert image to PDF using ImageMagick
	cmd := exec.Command("magick", tmpIn.Name(), pdfPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ImageMagick conversion failed: %w: %s", err, output)
	}
	defer os.Remove(pdfPath)

	// Open the resulting PDF
	f, err := os.Open(pdfPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Set headers
	if origName != "" {
		fn := url.PathEscape(strings.TrimSuffix(origName, filepath.Ext(origName)))
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename*=UTF-8''%s.pdf", fn))
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Cache-Control", "public, max-age=2592000, immutable")
	w.WriteHeader(status)

	_, err = io.Copy(w, f)
	return err
}

// ConvertImageReader converts an image from src to the target format
// supported formats: jpg, jpeg, png, tif, tiff, bmp, prn, gif, jfif, heic
func ConvertImageReader(src io.Reader, targetFormat string) (io.ReadCloser, error) {
	// Save input to temp file
	tmpIn, err := os.CreateTemp("", "img-*")
	if err != nil {
		return nil, err
	}
	defer tmpIn.Close()

	if _, err := io.Copy(tmpIn, src); err != nil {
		return nil, err
	}

	// Prepare output temp file
	base := strings.TrimSuffix(filepath.Base(tmpIn.Name()), filepath.Ext(tmpIn.Name()))
	tmpOut, err := os.CreateTemp("", base+"-*."+strings.ToLower(targetFormat))
	if err != nil {
		return nil, err
	}
	tmpOut.Close() // will be written by magick

	// Use ImageMagick to convert
	cmd := exec.Command("convert", tmpIn.Name(), tmpOut.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Remove(tmpOut.Name())
		return nil, fmt.Errorf("ImageMagick conversion failed: %w: %s", err, output)
	}

	// Open converted file for reading
	f, err := os.Open(tmpOut.Name())
	if err != nil {
		os.Remove(tmpOut.Name())
		return nil, err
	}

	// Wrap in ReadCloser that removes file on close
	rc := &tempFileReadCloser{f, tmpOut.Name()}
	return rc, nil
}

// tempFileReadCloser removes file when closed
type tempFileReadCloser struct {
	*os.File
	path string
}

func (t *tempFileReadCloser) Close() error {
	err1 := t.File.Close()
	err2 := os.Remove(t.path)
	if err1 != nil {
		return err1
	}
	return err2
}
