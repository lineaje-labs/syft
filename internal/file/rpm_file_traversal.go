package file

import (
	"io"
	"os"
	"path/filepath"

	"github.com/sassoftware/go-rpmutils"
)

// ExtractGlobsFromRPMToUniqueTempFile extracts paths matching the given globs within the given RPM to a temporary directory, returning file openers for each file extracted.
func ExtractGlobsFromRPMToUniqueTempFile(rpmPath, dir string, globs ...string) (map[string]Opener, error) {
	results := make(map[string]Opener)
	var err error
	// don't allow for full traversal, only select traversal from given paths
	if len(globs) == 0 {
		return results, nil
	}
	f, err := os.Open(rpmPath)
	if err != nil {
		return results, nil
	}
	defer f.Close()
	rpm, err := rpmutils.ReadRpm(f)
	if err != nil {
		return results, nil
	}
	var files int
	payload, err := rpm.PayloadReaderExtended()
	if err != nil {
		return results, nil
	}
	for {
		file, err := payload.Next()
		if err == io.EOF {
			break
		}
		if !matchesAnyGlob(file.Name(), globs...) {
			continue
		}

		// we have a file we want to extract....
		tempfilePrefix := filepath.Base(filepath.Clean(file.Name())) + "-"
		tempFile, err := os.CreateTemp(dir, tempfilePrefix)
		if err != nil {
			continue
		}
		// we shouldn't try and keep the tempfile open as the returned result may have several files, which takes up
		// resources (leading to "too many open files"). Instead we'll return a file opener to the caller which
		// provides a ReadCloser. It is up to the caller to handle closing the file explicitly.
		if err := safeCopy(tempFile, payload); err != nil {
			tempFile.Close()
			continue
		}
		results[file.Name()] = Opener{path: tempFile.Name()}
		tempFile.Close()
		files++
	}

	return results, nil
}
