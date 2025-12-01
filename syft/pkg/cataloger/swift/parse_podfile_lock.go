package swift

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

var _ generic.Parser = parsePodfileLock

type podfileLock struct {
	Pods            []any               `yaml:"PODS"`
	Dependencies    []string            `yaml:"DEPENDENCIES"`
	SpecRepos       map[string][]string `yaml:"SPEC REPOS"`
	SpecChecksums   map[string]string   `yaml:"SPEC CHECKSUMS"`
	PodfileChecksum string              `yaml:"PODFILE CHECKSUM"`
	Cocopods        string              `yaml:"COCOAPODS"`
}

// parsePodfileLock is a parser function for Podfile.lock contents, returning all cocoapods pods discovered.
func parsePodfileLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var podfile podfileLock
	if err := yaml.NewDecoder(reader).Decode(&podfile); err != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml: %w", err)
	}

	// Map of Pod name vs list of its dependencies
	// A pod name is a subspec, if it has "/" in it, and can be part of this list
	podNameVsDependencies := make(map[string][]string)
	for _, podInterface := range podfile.Pods {
		var podBlob []string
		switch v := podInterface.(type) {
		case map[string]interface{}:
			// This is for the following entry,
			// - FirebaseCore (10.7.0):
			//    - FirebaseCoreInternal (~> 10.0)
			//    - GoogleUtilities/Environment (~> 7.8)
			//    - GoogleUtilities/Logger (~> 7.8)
			for key, value := range v {
				podBlob = append(podBlob, key) // The parent pod
				subItems := value.([]interface{})
				for _, sub := range subItems {
					podBlob = append(podBlob, sub.(string))
				}
			}
		case string:
			podBlob = append(podBlob, v) // pod without any dependencies
		default:
			return nil, nil, fmt.Errorf("malformed podfile.lock")
		}
		// Each entry in podBlob is of the format - "FirebaseCore (10.7.0)"
		podName := strings.Split(podBlob[0], " ")[0]
		if len(podBlob) > 1 { // Indicates it has dependencies
			var dependencies []string
			for i := 1; i < len(podBlob); i++ {
				dependencies = append(dependencies, strings.Split(podBlob[i], " ")[0])  // Save only the name in the relationship
			}
			podNameVsDependencies[podName] = dependencies
		}
	}
	var pkgs []pkg.Package
	for _, podInterface := range podfile.Pods {
		var podBlob string
		switch v := podInterface.(type) {
		case map[string]any:
			for k := range v {
				podBlob = k
			}
		case string:
			podBlob = v
		default:
			return nil, nil, fmt.Errorf("malformed podfile.lock")
		}
		podName, podVersion, ok := strings.Cut(podBlob, " ")
		if !ok {
			return nil, nil, errors.New("malformed podfile.lock: pod has no version")
		}
		podVersion = strings.TrimSuffix(strings.TrimPrefix(podVersion, "("), ")")
		podRootPkg := strings.Split(podName, "/")[0]

		var pkgHash string
		pkgHash, exists := podfile.SpecChecksums[podRootPkg]
		if !exists {
			return nil, nil, fmt.Errorf("malformed podfile.lock: incomplete checksums")
		}
		var pkgDeps []string
		// Fetch the dependencies found in pkgs
		if deps, found := podNameVsDependencies[podName]; found {
			pkgDeps = deps
		}

		pkgs = append(
			pkgs,
			newCocoaPodsPackage(
				podName,
				podVersion,
				pkgHash,
				pkgDeps,
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	// since we would never expect to create relationships for packages across multiple podfile.lock files
	// we should do this on a file parser level (each podfile.lock) instead of a cataloger level (across all
	// podfile.lock files)
	return pkgs, dependency.Resolve(podfileLockDependencySpecifier, pkgs), unknown.IfEmptyf(pkgs, "unable to determine packages")
}
