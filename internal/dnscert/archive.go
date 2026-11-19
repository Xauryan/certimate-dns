package dnscert

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"path"
	"strings"
)

// Certificate archives can also contain Apache, Java, and IIS bundles for
// the same order. Read just the two Nginx files without extracting to disk.
func nginxArchiveMaterial(archive []byte, acceptDir func(string) bool, certSuffix string) (Material, error) {
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(z.File) > 256 {
		return Material{}, errProvider
	}
	var result Material
	for _, entry := range z.File {
		name := strings.ToLower(entry.Name)
		if !fs.ValidPath(name) || strings.ContainsRune(name, '\\') || !acceptDir(path.Dir(name)) || !entry.Mode().IsRegular() {
			continue
		}
		var target *string
		switch {
		case strings.HasSuffix(name, certSuffix):
			target = &result.Certificate
		case path.Ext(name) == ".key":
			target = &result.PrivateKey
		default:
			continue
		}
		const limit = 256 << 10
		if *target != "" || entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > limit {
			return Material{}, errProvider
		}
		reader, err := entry.Open()
		if err != nil {
			return Material{}, errProvider
		}
		data, err := io.ReadAll(io.LimitReader(reader, limit+1))
		closeErr := reader.Close()
		if err != nil || closeErr != nil || len(data) == 0 || len(data) > limit {
			return Material{}, errProvider
		}
		*target = string(data)
	}
	if result.Certificate == "" || result.PrivateKey == "" {
		return Material{}, errProvider
	}
	return result, nil
}
