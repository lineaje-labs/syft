package javascript

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parsePackageLock

// PackageLock represents a JavaScript package.lock json file
type PackageLock struct {
	Requires        bool `json:"requires"`
	LockfileVersion int  `json:"lockfileVersion"`
	Dependencies    map[string]Dependency
	Packages        map[string]Package
}

// Dependency represents a single package dependency listed in the package.lock json file
type Dependency struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

type Package struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	License   string `json:""`
}

// parsePackageLock parses a package-lock.json and returns the discovered JavaScript packages.
func parsePackageLock(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	// in the case we find package-lock.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(path) {
		return nil, nil, nil
	}

	var packages []*pkg.Package
	dec := json.NewDecoder(reader)

	for {
		var lock PackageLock
		if err := dec.Decode(&lock); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
		licenseMap := make(map[string]string)
		for _, pkgMeta := range lock.Packages {
			var sb strings.Builder
			sb.WriteString(pkgMeta.Resolved)
			sb.WriteString(pkgMeta.Integrity)
			licenseMap[sb.String()] = pkgMeta.License
		}

		for name, pkgMeta := range lock.Dependencies {
			var sb strings.Builder
			sb.WriteString(pkgMeta.Resolved)
			sb.WriteString(pkgMeta.Integrity)
			var licenses []string
			if license, exists := licenseMap[sb.String()]; exists {
				licenses = append(licenses, license)
			}
			packages = append(packages, &pkg.Package{
				Name:     name,
				Version:  pkgMeta.Version,
				Language: pkg.JavaScript,
				Type:     pkg.NpmPkg,
				Licenses: licenses,
			})
		}
	}

	return packages, nil, nil
}
