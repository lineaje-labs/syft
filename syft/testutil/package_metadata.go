package testutil

import (
	"testing"

	"github.com/lineaje-labs/syft/syft/internal/packagemetadata"
)

type PackageMetadataCompletionTester struct {
	*packagemetadata.CompletionTester
}

func NewPackageMetadataCompletionTester(t testing.TB, ignore ...any) *PackageMetadataCompletionTester {
	return &PackageMetadataCompletionTester{
		CompletionTester: packagemetadata.NewCompletionTester(t, ignore...),
	}
}
