package spdxhelpers

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func ExternalRefs(p pkg.Package) (externalRefs []ExternalRef) {
	externalRefs = make([]ExternalRef, 0)

	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: SecurityReferenceCategory,
			ReferenceLocator:  cpe.String(c),
			ReferenceType:     Cpe23ExternalRefType,
		})
	}

	if p.PURL != "" {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: PackageManagerReferenceCategory,
			ReferenceLocator:  p.PURL,
			ReferenceType:     PurlExternalRefType,
		})
	}

	switch meta := p.Metadata.(type) {
	// Java packages may specify the bazel label used to build it
	case pkg.JavaArchive:
		if meta.Manifest != nil {
			if _, createdByFound := meta.Manifest.Main["Created-By"]; createdByFound {
				if meta.Manifest.Main["Created-By"] == "bazel" {
					if _, targetLabelFound := meta.Manifest.Main["Target-Label"]; targetLabelFound {
						externalRefs = append(externalRefs, ExternalRef{
							ReferenceCategory: OtherReferenceCategory,
							ReferenceLocator:  meta.Manifest.Main["Target-Label"],
							ReferenceType:     BazelLabelExternalRefType,
						})
					}
				}
			}
		}
	}

	return externalRefs
}
