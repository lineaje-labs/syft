package swift

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newSwiftPackageManagerPackage(name, version, sourceURL, revision string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      swiftPackageManagerPackageURL(name, version, sourceURL),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.SwiftPkg,
		Language:  pkg.Swift,
		Metadata: pkg.SwiftPackageManagerResolvedEntry{
			Revision: revision,
		},
	}

	p.SetID()

	return p
}

func newCocoaPodsPackage(name, version, hash string, deps []string, locations ...file.Location) pkg.Package {
	p := pkg.Package{
		Name:      name,
		Version:   version,
		PURL:      cocoaPodsPackageURL(name, version),
		Locations: file.NewLocationSet(locations...),
		Type:      pkg.CocoapodsPkg,
		Language:  pkg.Swift,
		Metadata: pkg.CocoaPodfileLockEntry{
			Checksum: hash,
			Dependencies: deps,
		},
	}

	p.SetID()

	return p
}

func cocoaPodsPackageURL(name, version string) string {
	var qualifiers packageurl.Qualifiers
	var subPath string
	if strings.Contains(name, "/") {
		nameParts := strings.Split(name, "/")
		name = nameParts[0]
		if len(nameParts) > 1 {
			subPath = strings.Join(nameParts[1:], "/")
		}
	}

	return packageurl.NewPackageURL(
		packageurl.TypeCocoapods,
		"",
		name,
		version,
		qualifiers,
		subPath,
	).ToString()
}

func swiftPackageManagerPackageURL(name, version, sourceURL string) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeSwift,
		strings.Replace(sourceURL, "https://", "", 1),
		name,
		version,
		qualifiers,
		"",
	).ToString()
}
