package golang

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/licensecheck"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func Test_LicenseSearch(t *testing.T) {
	loc1 := file.NewLocation("github.com/someorg/somename@v0.3.2/LICENSE")
	loc2 := file.NewLocation("github.com/!cap!o!r!g/!cap!project@v4.111.5/LICENSE.txt")
	loc3 := file.NewLocation("github.com/someorg/strangelicense@v1.2.3/LiCeNsE.tXt")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := &bytes.Buffer{}
		uri := strings.TrimPrefix(strings.TrimSuffix(r.RequestURI, ".zip"), "/")

		parts := strings.Split(uri, "/@v/")
		modPath := parts[0]
		modVersion := parts[1]

		wd, err := os.Getwd()
		require.NoError(t, err)
		testDir := filepath.Join(wd, "test-fixtures", "licenses", "pkg", "mod", processCaps(modPath)+"@"+modVersion)

		archive := zip.NewWriter(buf)

		entries, err := os.ReadDir(testDir)
		require.NoError(t, err)
		for _, f := range entries {
			// the zip files downloaded contain a path to the repo that somewhat matches where it ends up on disk,
			// so prefix entries with something similar
			writer, err := archive.Create(path.Join(moduleDir(modPath, modVersion), f.Name()))
			require.NoError(t, err)
			contents, err := os.ReadFile(filepath.Join(testDir, f.Name()))
			require.NoError(t, err)
			_, err = writer.Write(contents)
			require.NoError(t, err)
		}

		err = archive.Close()
		require.NoError(t, err)

		w.Header().Add("Content-Length", fmt.Sprintf("%d", buf.Len()))

		_, err = w.Write(buf.Bytes())
		require.NoError(t, err)
	}))
	defer server.Close()

	wd, err := os.Getwd()
	require.NoError(t, err)

	localVendorDir := filepath.Join(wd, "test-fixtures", "licenses-vendor")

	licenseScanner := licenses.NewScanner(licensecheck.Scan, float64(75))

	tests := []struct {
		name     string
		version  string
		config   CatalogerConfig
		expected []pkg.License
	}{
		{
			name:    "github.com/someorg/somename",
			version: "v0.3.2",
			config: CatalogerConfig{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            filepath.Join(wd, "test-fixtures", "licenses", "pkg", "mod"),
			},
			expected: []pkg.License{{
				Value:          "Apache-2.0",
				SPDXExpression: "Apache-2.0",
				Type:           license.Concluded,
				URLs:           []string{"file://$GOPATH/pkg/mod/" + loc1.RealPath},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/CapORG/CapProject",
			version: "v4.111.5",
			config: CatalogerConfig{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            filepath.Join(wd, "test-fixtures", "licenses", "pkg", "mod"),
			},
			expected: []pkg.License{{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Concluded,
				URLs:           []string{"file://$GOPATH/pkg/mod/" + loc2.RealPath},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/someorg/strangelicense",
			version: "v1.2.3",
			config: CatalogerConfig{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            filepath.Join(wd, "test-fixtures", "licenses", "pkg", "mod"),
			},
			expected: []pkg.License{{
				Value:          "Apache-2.0",
				SPDXExpression: "Apache-2.0",
				Type:           license.Concluded,
				URLs:           []string{"file://$GOPATH/pkg/mod/" + loc3.RealPath},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/someorg/somename",
			version: "v0.3.2",
			config: CatalogerConfig{
				SearchRemoteLicenses: true,
				Proxies:              []string{server.URL},
			},
			expected: []pkg.License{{
				Value:          "Apache-2.0",
				SPDXExpression: "Apache-2.0",
				Type:           license.Concluded,
				URLs:           []string{server.URL + "/github.com/someorg/somename/@v/v0.3.2.zip#" + loc1.RealPath},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/CapORG/CapProject",
			version: "v4.111.5",
			config: CatalogerConfig{
				SearchRemoteLicenses: true,
				Proxies:              []string{server.URL},
			},
			expected: []pkg.License{{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Concluded,
				URLs:           []string{server.URL + "/github.com/CapORG/CapProject/@v/v4.111.5.zip#" + loc2.RealPath},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/CapORG/CapProject",
			version: "v4.111.5",
			config: CatalogerConfig{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            filepath.Join(wd, "test-fixtures"), // valid dir but does not find modules
				SearchRemoteLicenses:        true,
				Proxies:                     []string{server.URL},
			},
			expected: []pkg.License{{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Concluded,
				URLs:           []string{server.URL + "/github.com/CapORG/CapProject/@v/v4.111.5.zip#" + loc2.RealPath},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/someorg/somename",
			version: "v0.3.2",
			config: CatalogerConfig{
				SearchLocalVendorLicenses: true,
				LocalVendorDir:            localVendorDir,
			},
			expected: []pkg.License{{
				Value:          "Apache-2.0",
				SPDXExpression: "Apache-2.0",
				Type:           license.Concluded,
				URLs:           []string{"file://$GO_VENDOR/github.com/someorg/somename/LICENSE"},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/CapORG/CapProject",
			version: "v4.111.5",
			config: CatalogerConfig{
				SearchLocalVendorLicenses: true,
				LocalVendorDir:            localVendorDir,
			},
			expected: []pkg.License{{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Concluded,
				URLs:           []string{"file://$GO_VENDOR/github.com/!cap!o!r!g/!cap!project/LICENSE.txt"},
				Locations:      file.NewLocationSet(),
			}},
		},
		{
			name:    "github.com/someorg/strangelicense",
			version: "v1.2.3",
			config: CatalogerConfig{
				SearchLocalVendorLicenses: true,
				LocalVendorDir:            localVendorDir,
			},
			expected: []pkg.License{{
				Value:          "Apache-2.0",
				SPDXExpression: "Apache-2.0",
				Type:           license.Concluded,
				URLs:           []string{"file://$GO_VENDOR/github.com/someorg/strangelicense/LiCeNsE.tXt"},
				Locations:      file.NewLocationSet(),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := newGoLicenseResolver("", test.config)
			lics := l.getLicenses(context.Background(), licenseScanner, fileresolver.Empty{}, test.name, test.version)
			require.EqualValues(t, test.expected, lics)
		})
	}
}

func Test_processCaps(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "CycloneDX",
			expected: "!cyclone!d!x",
		},
		{
			name:     "Azure",
			expected: "!azure",
		},
		{
			name:     "xkcd",
			expected: "xkcd",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := processCaps(test.name)

			require.Equal(t, test.expected, got)
		})
	}
}

func Test_remotesForModule(t *testing.T) {
	allProxies := []string{"https://somewhere.org", "direct"}
	directProxy := []string{"direct"}

	tests := []struct {
		module   string
		noProxy  string
		expected []string
	}{
		{
			module:   "github.com/anchore/syft",
			expected: allProxies,
		},
		{
			module:   "github.com/anchore/sbom-action",
			noProxy:  "*/anchore/*",
			expected: directProxy,
		},
		{
			module:   "github.com/anchore/sbom-action",
			noProxy:  "*/user/mod,*/anchore/sbom-action",
			expected: directProxy,
		},
	}

	for _, test := range tests {
		t.Run(test.module, func(t *testing.T) {
			got := remotesForModule(allProxies, strings.Split(test.noProxy, ","), test.module)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_findVersionPath(t *testing.T) {
	f := os.DirFS("test-fixtures/zip-fs")
	vp := findVersionPath(f, ".")
	require.Equal(t, "github.com/someorg/somepkg@version", vp)
}

func Test_walkDirErrors(t *testing.T) {
	resolver := newGoLicenseResolver("", CatalogerConfig{})
	_, err := resolver.findLicensesInFS(context.Background(), licenses.NewScanner(licensecheck.Scan, float64(75)), "somewhere", badFS{})
	require.Error(t, err)
}

type badFS struct{}

func (b badFS) Open(_ string) (fs.File, error) {
	return nil, fmt.Errorf("error")
}

var _ fs.FS = (*badFS)(nil)

func Test_noLocalGoModDir(t *testing.T) {
	emptyTmp := t.TempDir()

	validTmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(validTmp, "mod@ver"), 0700|os.ModeDir))

	licenseScanner := licenses.NewScanner(licensecheck.Scan, float64(75))
	tests := []struct {
		name    string
		dir     string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "empty",
			dir:     "",
			wantErr: require.Error,
		},
		{
			name:    "invalid dir",
			dir:     filepath.Join(emptyTmp, "invalid-dir"),
			wantErr: require.Error,
		},
		{
			name:    "missing mod dir",
			dir:     emptyTmp,
			wantErr: require.Error,
		},
		{
			name:    "valid mod dir",
			dir:     validTmp,
			wantErr: require.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := newGoLicenseResolver("", CatalogerConfig{
				SearchLocalModCacheLicenses: true,
				LocalModCacheDir:            test.dir,
			})
			_, err := resolver.getLicensesFromLocal(context.Background(), licenseScanner, "mod", "ver")
			test.wantErr(t, err)
		})
	}
}

func TestLicenseConversion(t *testing.T) {
	inputLicenses := []pkg.License{
		{
			Value:          "Apache-2.0",
			SPDXExpression: "Apache-2.0",
			Type:           "concluded",
			URLs:           nil,
			Locations:      file.NewLocationSet(file.NewLocation("LICENSE")),
			Contents:       "",
		},
		{
			Value:          "UNKNOWN",
			SPDXExpression: "UNKNOWN_4d1cffe420916f2b706300ab63fcafaf35226a0ad3725cb9f95b26036cefae32",
			Type:           "declared",
			URLs:           nil,
			Locations:      file.NewLocationSet(file.NewLocation("LICENSE2")),
			Contents:       "NVIDIA Software License Agreement and CUDA Supplement to Software License Agreement",
		},
	}

	goLicenses := toGoLicenses(inputLicenses)

	result := toPkgLicenses(goLicenses)

	require.Equal(t, inputLicenses, result)
}
