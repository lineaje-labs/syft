package swift

import (
	"context"
	"fmt"
	"io"
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
	Pods            []interface{}       `yaml:"PODS"`
	Dependencies    []string            `yaml:"DEPENDENCIES"`
	SpecRepos       map[string][]string `yaml:"SPEC REPOS"`
	SpecChecksums   map[string]string   `yaml:"SPEC CHECKSUMS"`
	PodfileChecksum string              `yaml:"PODFILE CHECKSUM"`
	Cocopods        string              `yaml:"COCOAPODS"`
}

// parsePodfileLock is a parser function for Podfile.lock contents, returning all cocoapods pods discovered.
func parsePodfileLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read file: %w", err)
	}
	var podfile podfileLock
	if err = yaml.Unmarshal(bytes, &podfile); err != nil {
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
		case map[string]interface{}:
			for k := range v {
				podBlob = k
			}
		case string:
			podBlob = v
		default:
			return nil, nil, fmt.Errorf("malformed podfile.lock")
		}
		splits := strings.Split(podBlob, " ")
		podName := splits[0]
		podVersion := strings.TrimSuffix(strings.TrimPrefix(splits[1], "("), ")")
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
