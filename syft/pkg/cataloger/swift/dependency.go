package swift

import (
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func podfileLockDependencySpecifier(p pkg.Package) dependency.Specification {
	meta, ok := p.Metadata.(pkg.CocoaPodfileLockEntry)
	if !ok {
		log.Tracef("cataloger failed to extract podfile lock metadata for package %+v", p.Name)
		return dependency.Specification{}
	}

	// this package reference always includes the package name and no extras
	provides := []string{p.Name}

	var requires []string
	// add required dependencies
	for _, dep := range meta.Dependencies {
		// we always have the base package requirement without any extras to get base dependencies
		requires = append(requires, dep)
	}

	return dependency.Specification{
		ProvidesRequires: dependency.ProvidesRequires{
			Provides: provides,
			Requires: requires,
		},
	}
}
