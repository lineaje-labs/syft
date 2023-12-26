package java

import (
	"fmt"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
	internalFile "github.com/lineaje-labs/syft/internal/file"
)

var genericRpmGlobs = []string{
	"**/*.rpm",
}

// TODO: when the generic archive cataloger is implemented, this should be removed (https://github.com/anchore/syft/issues/246)
type genericRPMWrappedJavaArchiveParser struct {
	cfg ArchiveCatalogerConfig
}

func newGenericRPMWrappedJavaArchiveParser(cfg ArchiveCatalogerConfig) genericRPMWrappedJavaArchiveParser {
	return genericRPMWrappedJavaArchiveParser{
		cfg: cfg,
	}
}

// parseRPMJavaArchive is a parser function for java archive contents contained within rpm files.
func (grp *genericRPMWrappedJavaArchiveParser) parseRPMJavaArchive(
	resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser,
) ([]pkg.Package, []artifact.Relationship, error) {
	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(reader.Path(), reader)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}

	_cataloger := redhat.NewArchiveCataloger()
	var rpmPackages []pkg.Package
	rpmPackages, _, err = _cataloger.Catalog(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read files from java archive: %w", err)
	}

	var packages []pkg.Package
	var relationships []artifact.Relationship
	for _, rpmPackage := range rpmPackages {
		_packages, _relationships, err := discoverPkgsFromRPM(reader.Location, archivePath, contentPath, rpmPackage, grp.cfg)
		if err == nil {
			packages = append(packages, _packages...)
			relationships = append(relationships, _relationships...)
		}
	}
	return packages, relationships, nil
}

func discoverPkgsFromRPM(
	location file.Location, archivePath, contentPath string, parentPkg pkg.Package, cfg ArchiveCatalogerConfig,
) ([]pkg.Package, []artifact.Relationship, error) {
	openers, err := internalFile.ExtractGlobsFromRPMToUniqueTempFile(archivePath, contentPath, archiveFormatGlobs...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract files from tar: %w", err)
	}

	var relationships []artifact.Relationship
	_packages, _, err := discoverPkgsFromOpeners(location, openers, &parentPkg, cfg)
	if err == nil {
		for index := range _packages {
			id := _packages[index].ID()
			if id == "" {
				_packages[index].SetID()
			}
			_relationship := artifact.Relationship{
				From: parentPkg,
				To:   _packages[index],
				Type: artifact.ContainsRelationship,
			}
			relationships = append(relationships, _relationship)
		}
	}
	return _packages, relationships, err
}
