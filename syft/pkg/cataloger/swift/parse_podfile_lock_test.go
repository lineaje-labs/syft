package swift

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePodfileLock(t *testing.T) {
	fixture := "testdata/Podfile.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	mkPkg := func(name, version, purl, checksum string, deps []string) pkg.Package {
		return pkg.Package{
			Name:      name,
			Version:   version,
			PURL:      purl,
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum:     checksum,
				Dependencies: deps,
			},
		}
	}

	expectedPkgs := []pkg.Package{
		mkPkg("GlossButtonNode", "3.1.2", "pkg:cocoapods/GlossButtonNode@3.1.2",
			"4ea1197a744f2fb5fb875fe31caf17ded4762e8f",
			[]string{"Texture/Core", "TextureSwiftSupport"}),
		mkPkg("PINCache", "3.0.3", "pkg:cocoapods/PINCache@3.0.3",
			"7a8fc1a691173d21dbddbf86cd515de6efa55086",
			[]string{"PINCache/Arc-exception-safe", "PINCache/Core"}),
		mkPkg("PINCache/Arc-exception-safe", "3.0.3", "pkg:cocoapods/PINCache@3.0.3#Arc-exception-safe",
			"7a8fc1a691173d21dbddbf86cd515de6efa55086",
			[]string{"PINCache/Core"}),
		mkPkg("PINCache/Core", "3.0.3", "pkg:cocoapods/PINCache@3.0.3#Core",
			"7a8fc1a691173d21dbddbf86cd515de6efa55086",
			[]string{"PINOperation"}),
		mkPkg("PINOperation", "1.2.1", "pkg:cocoapods/PINOperation@1.2.1",
			"00c935935f1e8cf0d1e2d6b542e75b88fc3e5e20",
			nil),
		mkPkg("PINRemoteImage/Core", "3.0.3", "pkg:cocoapods/PINRemoteImage@3.0.3#Core",
			"f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			[]string{"PINOperation"}),
		mkPkg("PINRemoteImage/iOS", "3.0.3", "pkg:cocoapods/PINRemoteImage@3.0.3#iOS",
			"f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			[]string{"PINRemoteImage/Core"}),
		mkPkg("PINRemoteImage/PINCache", "3.0.3", "pkg:cocoapods/PINRemoteImage@3.0.3#PINCache",
			"f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			[]string{"PINCache", "PINRemoteImage/Core"}),
		mkPkg("Reveal-SDK", "33", "pkg:cocoapods/Reveal-SDK@33",
			"effba1c940b8337195563c425a6b5862ec875caa",
			nil),
		mkPkg("SwiftGen", "6.5.1", "pkg:cocoapods/SwiftGen@6.5.1",
			"a6d22010845f08fe18fbdf3a07a8e380fd22e0ea",
			nil),
		mkPkg("Texture", "3.1.0", "pkg:cocoapods/Texture@3.1.0",
			"2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			[]string{"Texture/AssetsLibrary", "Texture/Core", "Texture/MapKit", "Texture/Photos", "Texture/PINRemoteImage", "Texture/Video"}),
		mkPkg("Texture/AssetsLibrary", "3.1.0", "pkg:cocoapods/Texture@3.1.0#AssetsLibrary",
			"2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			[]string{"Texture/Core"}),
		mkPkg("Texture/Core", "3.1.0", "pkg:cocoapods/Texture@3.1.0#Core",
			"2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			nil),
		mkPkg("Texture/MapKit", "3.1.0", "pkg:cocoapods/Texture@3.1.0#MapKit",
			"2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			[]string{"Texture/Core"}),
		mkPkg("Texture/Photos", "3.1.0", "pkg:cocoapods/Texture@3.1.0#Photos",
			"2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			[]string{"Texture/Core"}),
		mkPkg("Texture/PINRemoteImage", "3.1.0", "pkg:cocoapods/Texture@3.1.0#PINRemoteImage",
			"2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			[]string{"PINRemoteImage/iOS", "PINRemoteImage/PINCache", "Texture/Core"}),
		mkPkg("Texture/Video", "3.1.0", "pkg:cocoapods/Texture@3.1.0#Video",
			"2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			[]string{"Texture/Core"}),
		mkPkg("TextureSwiftSupport", "3.13.0", "pkg:cocoapods/TextureSwiftSupport@3.13.0",
			"c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			[]string{"Texture/Core", "TextureSwiftSupport/Components", "TextureSwiftSupport/Experiments", "TextureSwiftSupport/Extensions", "TextureSwiftSupport/LayoutSpecBuilders"}),
		mkPkg("TextureSwiftSupport/Components", "3.13.0", "pkg:cocoapods/TextureSwiftSupport@3.13.0#Components",
			"c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			[]string{"Texture/Core", "TextureSwiftSupport/LayoutSpecBuilders"}),
		mkPkg("TextureSwiftSupport/Experiments", "3.13.0", "pkg:cocoapods/TextureSwiftSupport@3.13.0#Experiments",
			"c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			[]string{"Texture/Core"}),
		mkPkg("TextureSwiftSupport/Extensions", "3.13.0", "pkg:cocoapods/TextureSwiftSupport@3.13.0#Extensions",
			"c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			[]string{"Texture/Core"}),
		mkPkg("TextureSwiftSupport/LayoutSpecBuilders", "3.13.0", "pkg:cocoapods/TextureSwiftSupport@3.13.0#LayoutSpecBuilders",
			"c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			[]string{"Texture/Core"}),
		mkPkg("TinyConstraints", "4.0.2", "pkg:cocoapods/TinyConstraints@4.0.2",
			"7b7ccc0c485bb3bb47082138ff28bc33cd49897f",
			nil),
	}

	pkgsByName := make(map[string]pkg.Package, len(expectedPkgs))
	for _, p := range expectedPkgs {
		pkgsByName[p.Name] = p
	}
	rel := func(dep, consumer string) artifact.Relationship {
		return artifact.Relationship{
			From: pkgsByName[dep],
			To:   pkgsByName[consumer],
			Type: artifact.DependencyOfRelationship,
		}
	}

	expectedRelationships := []artifact.Relationship{
		rel("Texture/Core", "GlossButtonNode"),
		rel("TextureSwiftSupport", "GlossButtonNode"),
		rel("PINCache/Arc-exception-safe", "PINCache"),
		rel("PINCache/Core", "PINCache"),
		rel("PINCache/Core", "PINCache/Arc-exception-safe"),
		rel("PINOperation", "PINCache/Core"),
		rel("PINOperation", "PINRemoteImage/Core"),
		rel("PINRemoteImage/Core", "PINRemoteImage/iOS"),
		rel("PINCache", "PINRemoteImage/PINCache"),
		rel("PINRemoteImage/Core", "PINRemoteImage/PINCache"),
		rel("Texture/AssetsLibrary", "Texture"),
		rel("Texture/Core", "Texture"),
		rel("Texture/MapKit", "Texture"),
		rel("Texture/Photos", "Texture"),
		rel("Texture/PINRemoteImage", "Texture"),
		rel("Texture/Video", "Texture"),
		rel("Texture/Core", "Texture/AssetsLibrary"),
		rel("Texture/Core", "Texture/MapKit"),
		rel("Texture/Core", "Texture/Photos"),
		rel("PINRemoteImage/iOS", "Texture/PINRemoteImage"),
		rel("PINRemoteImage/PINCache", "Texture/PINRemoteImage"),
		rel("Texture/Core", "Texture/PINRemoteImage"),
		rel("Texture/Core", "Texture/Video"),
		rel("Texture/Core", "TextureSwiftSupport"),
		rel("TextureSwiftSupport/Components", "TextureSwiftSupport"),
		rel("TextureSwiftSupport/Experiments", "TextureSwiftSupport"),
		rel("TextureSwiftSupport/Extensions", "TextureSwiftSupport"),
		rel("TextureSwiftSupport/LayoutSpecBuilders", "TextureSwiftSupport"),
		rel("Texture/Core", "TextureSwiftSupport/Components"),
		rel("TextureSwiftSupport/LayoutSpecBuilders", "TextureSwiftSupport/Components"),
		rel("Texture/Core", "TextureSwiftSupport/Experiments"),
		rel("Texture/Core", "TextureSwiftSupport/Extensions"),
		rel("Texture/Core", "TextureSwiftSupport/LayoutSpecBuilders"),
	}

	pkgtest.TestFileParser(t, fixture, parsePodfileLock, expectedPkgs, expectedRelationships)
}

func Test_corruptPodfile(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/glob-paths/src/Podfile.lock").
		WithError().
		TestParser(t, parsePodfileLock)
}

func TestParsePodfileLock_podWithoutVersion(t *testing.T) {
	// a pod entry is "Name (version)"; one without the version used to index past the end of the split
	contents := "PODS:\n  - Foo\nSPEC CHECKSUMS:\n  Foo: abc\n"
	reader := file.NewLocationReadCloser(file.NewLocation("Podfile.lock"), io.NopCloser(strings.NewReader(contents)))

	var err error
	require.NotPanics(t, func() {
		_, _, err = parsePodfileLock(context.Background(), nil, nil, reader)
	})
	require.ErrorContains(t, err, "has no version")
}
