package ziputil

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/gen2brain/go-unarr"
)

func ListFilesInArchive(zipBytes []byte) ([]string, error) {
	a, err := unarr.NewArchiveFromMemory(zipBytes)
	if err != nil {
		return nil, fmt.Errorf("nepavyko atidaryti archyvo: %w", err)
	}
	defer a.Close()

	return a.List()
}

func GetFileFromZipArchive(zipBytes []byte, filename string) (io.ReadCloser, error) {
	rdr, err := bytes.NewReader(zipBytes))
	if err != nil {
		return nil, err
	}
	r, err := zip.NewReader(rdr)
	if err != nil {
		return r, err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == filename {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("nepavyko atidaryti failo %q: %w", filename, err)
			}
			return rc, nil
		}
	}
	return nil, fmt.Errorf("failas %q zip’e nerastas", filename)
}

func GetFileFromArchive(archiveBytes []byte, filename string) (io.ReadCloser, error) {
	a, err := unarr.NewArchiveFromMemory(archiveBytes)
	if err != nil {
		return nil, fmt.Errorf("nepavyko atidaryti archyvo: %w", err)
	}

	defer func() {
		if err != nil {
			a.Close()
		}
	}()

	err = a.EntryFor(filename)
	if err != nil {
		return nil, fmt.Errorf("failas %q nerastas archyve: %w", filename, err)
	}
	defer a.Close()

	b, err := a.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("nepavyko nuskaityti failo %q: %w", filename, err)
	}

	return io.NopCloser(bytes.NewReader(b)), nil
}

// GetFileFromZip suranda faile esantį įrašą pagal filename ir grąžina jo turinį kaip io.ReadCloser.
// filename lyginamas pagal basename (pvz. "failas.pdf" ras "dir/sub/failas.pdf").
// Grąžina nil, nil jei failas nerastas.
func GetFileFromZip(zipBytes []byte, filename string) (io.ReadCloser, error) {
	r := bytes.NewReader(zipBytes)
	zr, err := zip.NewReader(r, int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("nepavyko atidaryti zip: %w", err)
	}

	target := strings.ToLower(path.Base(filename))

	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/") {
			continue // katalogas
		}
		if strings.ToLower(path.Base(f.Name)) == target {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("nepavyko atidaryti failo %q: %w", f.Name, err)
			}
			return rc, nil
		}
	}

	return nil, fmt.Errorf("failas %q zip’e nerastas", filename)
}
