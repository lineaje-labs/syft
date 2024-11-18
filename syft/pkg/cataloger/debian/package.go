package debian

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

const (
	md5sumsExt      = ".md5sums"
	conffilesExt    = ".conffiles"
	controlFilesExt = ".control"
	docsPath        = "/usr/share/doc"
)

func newDpkgPackage(d pkg.DpkgDBEntry, dbLocation file.Location, resolver file.Resolver, release *linux.Release) pkg.Package {
	// TODO: separate pr to license refactor, but explore extracting dpkg-specific license parsing into a separate function
	licenses := make([]pkg.License, 0)
	p := pkg.Package{
		Name:      d.Package,
		Version:   d.Version,
		Licenses:  pkg.NewLicenseSet(licenses...),
		Locations: file.NewLocationSet(dbLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		PURL:      packageURL(d, release, dbLocation),
		Type:      pkg.DebPkg,
		Metadata:  d,
	}

	if resolver != nil {
		// the current entry only has what may have been listed in the status file, however, there are additional
		// files that are listed in multiple other locations. We should retrieve them all and merge the file lists
		// together.
		mergeFileListing(resolver, dbLocation, &p)

		// fetch additional data from the copyright file to derive the license information
		addLicenses(resolver, dbLocation, &p)

		// fetch additional optional data from the control for description and license information
		addFieldsFromControlFile(resolver, dbLocation, &p)
	}

	p.SetID()

	return p
}

// PackageURL returns the PURL for the specific Debian package (see https://github.com/package-url/purl-spec)
// If file location has "/opkg/" (OpenWrt) in it, then the PackageURL is customized
func packageURL(m pkg.DpkgDBEntry, distro *linux.Release, dbLocation file.Location) string {
	if distro != nil && (distro.ID == "debian" || internal.StringInSlice("debian", distro.IDLike)) {
		qualifiers := map[string]string{
			pkg.PURLQualifierArch: m.Architecture,
		}

		if m.Source != "" {
			if m.SourceVersion != "" {
				qualifiers[pkg.PURLQualifierUpstream] = fmt.Sprintf("%s@%s", m.Source, m.SourceVersion)
			} else {
				qualifiers[pkg.PURLQualifierUpstream] = m.Source
			}
		}

		return packageurl.NewPackageURL(
			packageurl.TypeDebian,
			distro.ID,
			m.Package,
			m.Version,
			pkg.PURLQualifiers(
				qualifiers,
				distro,
			),
			"",
		).ToString()

	} else if strings.Contains(dbLocation.AccessPath, "/opkg/") {
		qualifiers := map[string]string{
			pkg.PURLQualifierArch: m.Architecture,
		}

		if m.Source != "" {
			if m.SourceVersion != "" {
				qualifiers[pkg.PURLQualifierUpstream] = fmt.Sprintf("%s@%s", m.Source, m.SourceVersion)
			} else {
				qualifiers[pkg.PURLQualifierUpstream] = m.Source
			}
		}

		return packageurl.NewPackageURL(
			"opkg",
			"openwrt",
			m.Package,
			m.Version,
			nil,
			"",
		).ToString()
	} else {
		return ""
	}
}

func addLicenses(resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	metadata, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.WithFields("package", p).Warn("unable to extract DPKG metadata to add licenses")
		return
	}

	// get license information from the copyright file
	copyrightReader, copyrightLocation := fetchCopyrightContents(resolver, dbLocation, metadata)

	if copyrightReader != nil && copyrightLocation != nil {
		defer internal.CloseAndLogError(copyrightReader, copyrightLocation.AccessPath)
		// attach the licenses
		licenseStrs := parseLicensesFromCopyright(copyrightReader)
		for _, licenseStr := range licenseStrs {
			p.Licenses.Add(pkg.NewLicenseFromLocations(licenseStr, copyrightLocation.WithoutAnnotations()))
		}
		// keep a record of the file where this was discovered
		p.Locations.Add(*copyrightLocation)
	}
}

func mergeFileListing(resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	metadata, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.WithFields("package", p).Warn("unable to extract DPKG metadata to file listing")
		return
	}

	// get file listing (package files + additional config files)
	files, infoLocations := getAdditionalFileListing(resolver, dbLocation, metadata)
loopNewFiles:
	for _, newFile := range files {
		for _, existingFile := range metadata.Files {
			if existingFile.Path == newFile.Path {
				// skip adding this file since it already exists
				continue loopNewFiles
			}
		}
		metadata.Files = append(metadata.Files, newFile)
	}

	// sort files by path
	sort.SliceStable(metadata.Files, func(i, j int) bool {
		return metadata.Files[i].Path < metadata.Files[j].Path
	})

	// persist alterations
	p.Metadata = metadata

	// persist location information from each new source of information
	p.Locations.Add(infoLocations...)
}

func getAdditionalFileListing(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) ([]pkg.DpkgFileRecord, []file.Location) {
	// ensure the default value for a collection is never nil since this may be shown as JSON
	var files = make([]pkg.DpkgFileRecord, 0)
	var locations []file.Location

	md5Reader, md5Location := fetchMd5Contents(resolver, dbLocation, m)

	if md5Reader != nil && md5Location != nil {
		defer internal.CloseAndLogError(md5Reader, md5Location.AccessPath)
		// attach the file list
		files = append(files, parseDpkgMD5Info(md5Reader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *md5Location)
	}

	conffilesReader, conffilesLocation := fetchConffileContents(resolver, dbLocation, m)

	if conffilesReader != nil && conffilesLocation != nil {
		defer internal.CloseAndLogError(conffilesReader, conffilesLocation.AccessPath)
		// attach the file list
		files = append(files, parseDpkgConffileInfo(conffilesReader)...)

		// keep a record of the file where this was discovered
		locations = append(locations, *conffilesLocation)
	}

	return files, locations
}

func addFieldsFromControlFile(resolver file.Resolver, dbLocation file.Location, p *pkg.Package) {
	metadata, ok := p.Metadata.(pkg.DpkgDBEntry)
	if !ok {
		log.WithFields("package", p).Warn("unable to extract DPKG metadata to add data from control file")
		return
	}

	// get additional details from the control file
	controlFileReader, controlFileLocation := fetchControlFileContents(resolver, dbLocation, metadata)

	if controlFileReader != nil && controlFileLocation != nil {
		defer internal.CloseAndLogError(controlFileReader, controlFileLocation.AccessPath)
		// add additional data from control file
		controlFileBuffedReader := bufio.NewReader(controlFileReader)
		entry, err := parseDpkgControlEntry(controlFileBuffedReader)
		if err != nil {
			return
		}
		var metadataModified bool
		if len(metadata.Description) == 0 && len(entry.Description) > 0 {
			metadata.Description = entry.Description
			metadataModified = true
		}
		if len(metadata.Source) == 0 && len(entry.Source) > 0 {
			metadata.Source = entry.Source
			metadataModified = true
		}
		if metadataModified {
			// persist alterations
			p.Metadata = metadata
		}
		if len(entry.License) > 0 {
			p.Licenses.Add(pkg.NewLicenseFromLocations(entry.License, controlFileLocation.WithoutAnnotations()))
		}
		// keep a record of the file where this was discovered
		p.Locations.Add(*controlFileLocation)
		// "kernel" is not a valid package name, change it to "linux" so that CPE lookups for vulnerability passes
		if p.Name == "kernel" {
			p.Name = "linux"
		}
	}
}

func fetchControlFileContents(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) (io.ReadCloser, *file.Location) {
	var controlFileReader io.ReadCloser
	var err error

	if resolver == nil {
		return nil, nil
	}
	parentPath := filepath.Dir(dbLocation.RealPath)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", m.Package+controlFilesExt))
	if location == nil {
		return nil, nil
	}
	l := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)
	controlFileReader, err = resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Warnf("failed to fetch deb control contents (package=%s): %+v", m.Package, err)
	}
	return controlFileReader, &l
}

func fetchMd5Contents(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) (io.ReadCloser, *file.Location) {
	var md5Reader io.ReadCloser
	var err error

	if resolver == nil {
		return nil, nil
	}

	// for typical debian-base distributions, the installed package info is at /var/lib/dpkg/status
	// and the md5sum information is under /var/lib/dpkg/info/; however, for distroless the installed
	// package info is across multiple files under /var/lib/dpkg/status.d/ and the md5sums are contained in
	// the same directory
	searchPath := filepath.Dir(dbLocation.RealPath)

	if !strings.HasSuffix(searchPath, "status.d") {
		searchPath = path.Join(searchPath, "info")
	}

	// look for /var/lib/dpkg/info/NAME:ARCH.md5sums
	name := md5Key(m)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(searchPath, name+md5sumsExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.md5sums
		location = resolver.RelativeFileByPath(dbLocation, path.Join(searchPath, m.Package+md5sumsExt))
	}

	if location == nil {
		return nil, nil
	}

	// this is unexpected, but not a show-stopper
	md5Reader, err = resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Warnf("failed to fetch deb md5 contents (package=%s): %+v", m.Package, err)
	}

	l := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)

	return md5Reader, &l
}

func fetchConffileContents(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) (io.ReadCloser, *file.Location) {
	var reader io.ReadCloser
	var err error

	if resolver == nil {
		return nil, nil
	}

	parentPath := filepath.Dir(dbLocation.RealPath)

	// look for /var/lib/dpkg/info/NAME:ARCH.conffiles
	name := md5Key(m)
	location := resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", name+conffilesExt))

	if location == nil {
		// the most specific key did not work, fallback to just the name
		// look for /var/lib/dpkg/info/NAME.conffiles
		location = resolver.RelativeFileByPath(dbLocation, path.Join(parentPath, "info", m.Package+conffilesExt))
	}

	if location == nil {
		return nil, nil
	}

	// this is unexpected, but not a show-stopper
	reader, err = resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Warnf("failed to fetch deb conffiles contents (package=%s): %+v", m.Package, err)
	}

	l := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)

	return reader, &l
}

func fetchCopyrightContents(resolver file.Resolver, dbLocation file.Location, m pkg.DpkgDBEntry) (io.ReadCloser, *file.Location) {
	if resolver == nil {
		return nil, nil
	}

	// look for /usr/share/docs/NAME/copyright files
	copyrightPath := path.Join(docsPath, m.Package, "copyright")
	location := resolver.RelativeFileByPath(dbLocation, copyrightPath)

	// we may not have a copyright file for each package, ignore missing files
	if location == nil {
		return nil, nil
	}

	reader, err := resolver.FileContentsByLocation(*location)
	if err != nil {
		log.Warnf("failed to fetch deb copyright contents (package=%s): %s", m.Package, err)
	}
	defer internal.CloseAndLogError(reader, location.RealPath)

	l := location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation)

	return reader, &l
}

func md5Key(metadata pkg.DpkgDBEntry) string {
	contentKey := metadata.Package
	if metadata.Architecture != "" && metadata.Architecture != "all" {
		contentKey = contentKey + ":" + metadata.Architecture
	}
	return contentKey
}
