package python

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	// given the example requirement:
	//    requests[security] == 2.8.* ; python_version < "2.7" and sys_platform == "linux"  \
	//      --hash=sha256:a9b3aaa1904eeb78e32394cd46c6f37ac0fb4af6dc488daa58971bdc7d7fcaf3 \
	//      --hash=sha256:e9535b8c84dc9571a48999094fda7f33e63c3f1b74f3e5f3ac0105a58405bb65  # some comment

	// namePattern matches: requests[security]
	namePattern = `(?P<name>\w[\w\[\],\s-_]+)`

	// versionConstraintPattern matches: == 2.8.*
	versionConstraintPattern = `(?P<versionConstraint>([^\S\r\n]*[~=>!<]+\s*[0-9a-zA-Z.*]+[^\S\r\n]*,?)+)?(@[^\S\r\n]*(?P<url>[^;]*))?`

	// markersPattern matches: python_version < "2.7" and sys_platform == "linux"
	markersPattern = `(;(?P<markers>.*))?`

	// hashesPattern matches: --hash=sha256:a9b3aaa1904eeb78e32394cd46c6f37ac0fb4af6dc488daa58971bdc7d7fcaf3 --hash=sha256:e9535b8c84dc9571a48999094fda7f33e63c3f1b74f3e5f3ac0105a58405bb65
	hashesPattern = `(?P<hashes>([^\S\r\n]*--hash=[a-zA-Z0-9:]+)+)?`

	// whiteSpaceNoNewlinePattern matches: (any whitespace character except for \r and \n)
	whiteSpaceNoNewlinePattern = `[^\S\r\n]*`
)

type pypiJson struct {
	LastSerial int                      `json:"last_serial"`
	Releases   map[string][]pypiRelease `json:"releases,omitempty"`
}

type pypiRelease struct {
	Version           string    // This is filled by us and not by PyPI
	UploadTimeIso8601 time.Time `json:"upload_time_iso_8601"`
	Yanked            bool      `json:"yanked"`
}

var requirementPattern = regexp.MustCompile(
	`^` +
		whiteSpaceNoNewlinePattern +
		namePattern +
		whiteSpaceNoNewlinePattern +
		versionConstraintPattern +
		markersPattern +
		hashesPattern,
)

type unprocessedRequirement struct {
	Name              string `mapstructure:"name"`
	VersionConstraint string `mapstructure:"versionConstraint"`
	Markers           string `mapstructure:"markers"`
	URL               string `mapstructure:"url"`
	Hashes            string `mapstructure:"hashes"`
}

func newRequirement(raw string) *unprocessedRequirement {
	var r unprocessedRequirement

	values := internal.MatchNamedCaptureGroups(requirementPattern, raw)

	if err := mapstructure.Decode(values, &r); err != nil {
		return nil
	}

	r.Name = strings.TrimSpace(r.Name)
	r.VersionConstraint = strings.TrimSpace(r.VersionConstraint)
	r.Markers = strings.TrimSpace(r.Markers)
	r.URL = strings.TrimSpace(r.URL)
	r.Hashes = strings.TrimSpace(r.Hashes)

	if r.Name == "" {
		return nil
	}

	return &r
}

type requirementsParser struct {
	guessUnpinnedRequirements bool
}

func newRequirementsParser(cfg CatalogerConfig) requirementsParser {
	return requirementsParser{
		guessUnpinnedRequirements: cfg.GuessUnpinnedRequirements,
	}
}

// parseRequirementsTxt takes a Python requirements.txt file, returning all Python packages that are locked to a
// specific version.
func (rp requirementsParser) parseRequirementsTxt(
	_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser,
) ([]pkg.Package, []artifact.Relationship, error) {
	var packages []pkg.Package

	scanner := bufio.NewScanner(reader)
	var lastLine string
	for scanner.Scan() {
		line := trimRequirementsTxtLine(scanner.Text())

		if lastLine != "" {
			line = lastLine + line
			lastLine = ""
		}

		// remove line continuations... smashes the file into a single line
		if strings.HasSuffix(line, "\\") {
			// this line is a continuation of the previous line
			lastLine += strings.TrimSuffix(line, "\\")
			continue
		}

		if line == "" {
			// nothing to parse on this line
			continue
		}

		if strings.HasPrefix(line, "-e") {
			// editable packages aren't parsed (yet)
			continue
		}

		req := newRequirement(line)
		if req == nil {
			log.WithFields("path", reader.RealPath).Warnf("unable to parse requirements.txt line: %q", line)
			continue
		}

		name := removeExtras(req.Name)
		version := parseVersion(name, req.VersionConstraint, rp.guessUnpinnedRequirements)

		if version == "" {
			log.WithFields("path", reader.RealPath).Tracef("unable to determine package version in requirements.txt line: %q", line)
			continue
		}

		packages = append(
			packages,
			newPackageForRequirementsWithMetadata(
				name,
				version,
				pkg.PythonRequirementsEntry{
					Name:              name,
					Extras:            parseExtras(req.Name),
					VersionConstraint: req.VersionConstraint,
					URL:               parseURL(req.URL),
					Markers:           req.Markers,
				},
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse python requirements file: %w", err)
	}

	return packages, nil, nil
}

func parseVersion(name string, version string, guessFromConstraint bool) string {
	if isPinnedConstraint(version) {
		return strings.TrimSpace(strings.ReplaceAll(version, "==", ""))
	}

	if guessFromConstraint {
		return guessVersion(name, version)
	}

	return ""
}

func isPinnedConstraint(version string) bool {
	return strings.Contains(version, "==") && !strings.ContainsAny(version, "*,<>!")
}

func guessVersion(name string, constraint string) string {
	if name == "" { // Package name is required to guess the version
		return ""
	}
	// Query pypi for this package name and parse the JSON to extract a list of released versions
	pypiPackageJSONURL := fmt.Sprintf("%v/pypi/%v/json", "https://pypi.org", name)
	req, err := http.NewRequest(http.MethodGet, pypiPackageJSONURL, nil)
	if err != nil {
		return ""
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "" // network could be unreachable
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "" // reqeust / response to pypi could have timed out
	}

	pypiPackageJSONBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "" // http response data read could be corrupt
	}
	var pypiPackageJSONData pypiJson
	err = json.Unmarshal(pypiPackageJSONBytes, &pypiPackageJSONData)
	if err != nil {
		return "" // JSON read from pypi could be corrupt
	}
	if pypiPackageJSONData.Releases == nil {
		return "" // JSON read from pypi could be corrupt
	}
	var pypiPackageReleases []pypiRelease
	for pypiPackageReleaseVer, releases := range pypiPackageJSONData.Releases {
		for _, release := range releases {
			release.Version = pypiPackageReleaseVer
			pypiPackageReleases = append(pypiPackageReleases, release)
			break
		}
	}

	// Releases are checked in reverse order of their release. They have a better chance of matching the constraints
	slices.SortStableFunc(pypiPackageReleases, func(a, b pypiRelease) int { return a.UploadTimeIso8601.Compare(b.UploadTimeIso8601) })
	slices.Reverse(pypiPackageReleases)
	classifiers, err := pep440.NewSpecifiers(constraint)
	if err != nil && len(constraint) > 0 { // If constraint had a value, and it could not be parsed, then return a zero value
		return ""
	}
	for _, pypiPackageRelease := range pypiPackageReleases {
		// Skip any version that has "rc" in it
		if strings.Contains(pypiPackageRelease.Version, "rc") {
			continue
		}
		// Skip any version that was yanked
		if pypiPackageRelease.Yanked {
			continue
		}
		v, err := pep440.Parse(pypiPackageRelease.Version)
		if err != nil {
			continue
		}
		// If no constraints was set, then use the latest release version in pypi
		if len(constraint) == 0 {
			return pypiPackageRelease.Version
		}
		if classifiers.Check(v) {
			return pypiPackageRelease.Version
		}
	}
	return ""
}

// trimRequirementsTxtLine removes content from the given requirements.txt line
// that should not be considered for parsing.
func trimRequirementsTxtLine(line string) string {
	line = strings.TrimSpace(line)
	line = removeTrailingComment(line)

	return line
}

// removeTrailingComment takes a requirements.txt line and strips off comment strings.
func removeTrailingComment(line string) string {
	parts := strings.SplitN(line, "#", 2)
	if len(parts) < 2 {
		// there aren't any comments

		return line
	}

	return parts[0]
}

func removeExtras(packageName string) string {
	start := strings.Index(packageName, "[")
	if start == -1 {
		return packageName
	}

	return strings.TrimSpace(packageName[:start])
}

func parseExtras(packageName string) []string {
	var extras []string

	start := strings.Index(packageName, "[")
	stop := strings.Index(packageName, "]")
	if start == -1 || stop == -1 {
		return extras
	}

	extraString := packageName[start+1 : stop]
	for _, extra := range strings.Split(extraString, ",") {
		extras = append(extras, strings.TrimSpace(extra))
	}
	return extras
}

func parseURL(line string) string {
	parts := strings.Split(line, "@")

	if len(parts) > 1 {
		desiredIndex := -1

		for index, part := range parts {
			part := strings.TrimFunc(part, func(r rune) bool {
				return !unicode.IsLetter(r) && !unicode.IsNumber(r)
			})

			if strings.HasPrefix(part, "git") {
				desiredIndex = index
				break
			}
		}

		if desiredIndex != -1 {
			return strings.TrimSpace(strings.Join(parts[desiredIndex:], "@"))
		}
	}

	return ""
}
