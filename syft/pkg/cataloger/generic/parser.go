package generic

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

type Environment struct {
	LinuxRelease *linux.Release
}

type Parser func(context.Context, file.Resolver, *Environment, file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error)
