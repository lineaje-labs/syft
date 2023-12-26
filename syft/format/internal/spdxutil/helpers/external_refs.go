package helpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func ExternalRefs(p pkg.Package) (externalRefs []ExternalRef) {
	externalRefs = make([]ExternalRef, 0)

	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: SecurityReferenceCategory,
			ReferenceLocator:  c.Attributes.String(),
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
			if createdBy, createdByFound := meta.Manifest.Main.Get("Created-By"); createdByFound {
				if createdBy == "bazel" {
					if targetLabel, targetLabelFound := meta.Manifest.Main.Get("Target-Label"); targetLabelFound {
						externalRefs = append(externalRefs, ExternalRef{
							ReferenceCategory: OtherReferenceCategory,
							ReferenceLocator:  targetLabel,
							ReferenceType:     BazelLabelExternalRefType,
						})
					}
				}
			}
		}
	default:
	}

	return externalRefs
}
