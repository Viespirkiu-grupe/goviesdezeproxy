package ziputil

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/gen2brain/go-unarr"
	"github.com/jhillyerd/enmime"
	"github.com/mholt/archives"
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
	rdr := bytes.NewReader(zipBytes)
	r, err := zip.NewReader(rdr, int64(len(zipBytes)))
	if err != nil {
		return nil, err
	}

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

func IdentityFilesV2(archiveBytes []byte) ([]string, error) {
	format, stream, err := archives.Identify(context.TODO(), "file", bytes.NewReader(archiveBytes))
	if err != nil {
		return nil, fmt.Errorf("nepavyko atidaryti archyvo: %w", err)
	}
	extractor, ok := format.(archives.Extractor)
	if !ok {
		return nil, fmt.Errorf("formatas %T nepalaiko failų išskleidimo (gali būti, kad tai ne archyvas)", format)
	}
	var names []string
	err = extractor.Extract(context.TODO(), stream, func(ctx context.Context, info archives.FileInfo) error {
		if info.IsDir() {
			return nil
		}
		names = append(names, info.Name())
		return nil
	})

	return names, nil
}

func GetFileFromArchiveV2(archiveBytes []byte, filename string) (io.ReadCloser, error) {
	var buf bytes.Buffer
	format, stream, err := archives.Identify(context.TODO(), filename, bytes.NewReader(archiveBytes))
	if err != nil {
		return nil, fmt.Errorf("nepavyko atidaryti archyvo: %w", err)
	}
	extractor, ok := format.(archives.Extractor)
	if !ok {
		return nil, fmt.Errorf("formatas %T nepalaiko failų išskleidimo (gali būti, kad tai ne archyvas)", format)
	}
	err = extractor.Extract(context.TODO(), stream, func(ctx context.Context, info archives.FileInfo) error {
		if info.IsDir() {
			return nil
		}
		fh, err := info.Open()
		if err != nil {
			return fmt.Errorf("nepavyko atidaryti failo %q: %w", filename, err)
		}
		defer fh.Close()
		buf.ReadFrom(fh)
		return nil
	})
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil

}

func ListFilesFromRarArchive(archiveBytes []byte) ([]string, error) {
	var format archives.Rar
	var names []string
	err := format.Extract(context.TODO(), bytes.NewReader(archiveBytes), func(ctx context.Context, info archives.FileInfo) error {
		names = append(names, info.Name())
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("nepavyko atidaryti archyvo: %w", err)
	}
	return names, nil
}

func GetFileFromRarArchive(archiveBytes []byte, filename string) (io.ReadCloser, error) {
	var format archives.Rar
	var buf bytes.Buffer
	err := format.Extract(context.TODO(), bytes.NewReader(archiveBytes), func(ctx context.Context, info archives.FileInfo) error {
		fh, err := info.Open()
		if err != nil {
			return fmt.Errorf("nepavyko atidaryti failo %q: %w", filename, err)
		}
		defer fh.Close()
		buf.ReadFrom(fh)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("nepavyko atidaryti archyvo: %w", err)
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
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

func ExtractEmlAttachments(in []byte, filename string, idx string) (io.ReadCloser, error) {
	// 1. Atidarome failą
	f := bytes.NewReader(in)
	index, _ := strconv.Atoi(idx)

	// 2. Išparsiname (Enmime padaro visą sunkų darbą)
	env, err := enmime.ReadEnvelope(f)
	if err != nil {
		return nil, fmt.Errorf("klaida skaitant EML: %w", err)
	}

	// 3. Išsaugome prisegtukus
	var buf bytes.Buffer
	i := 0
	for _, att := range env.Attachments {
		if att.FileName != filename {
			continue
		}
		i++
		if i < index && index != 0 {
			continue
		}
		// err := os.WriteFile(fullPath, att.Content, 0644)
		buf.ReadFrom(bytes.NewReader(att.Content))
		break
		// if err != nil {
		// return fmt.Errorf("nepavyko įrašyti %s: %w", att.FileName, err)
		// }
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

func ConvertMsgToEml(in []byte) ([]byte, error) {
	file := bytes.NewReader(in)
	_ = file

	tmpFileName, _ := os.CreateTemp("", "msg-*.msg")
	defer os.Remove(tmpFileName.Name())
	// log.Printf("Laikinas MSG failas: %s", tmpFileName.Name())
	os.WriteFile(tmpFileName.Name(), in, 0755)

	cmd := exec.Command("msgconvert", "--outfile", "-", tmpFileName.Name())
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go func() {
		io.Copy(os.Stderr, stderr)
	}()
	var buf bytes.Buffer
	go func() {
		io.Copy(&buf, stdout)
	}()
	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("nepavyko konvertuoti MSG į EML: %w", err)
	}
	err = cmd.Wait()
	if err != nil {
		return nil, fmt.Errorf("nepavyko konvertuoti MSG į EML: %w", err)
	}

	return buf.Bytes(), nil
}
