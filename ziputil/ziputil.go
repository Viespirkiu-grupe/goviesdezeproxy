package ziputil

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
)

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
