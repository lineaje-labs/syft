package java

import "github.com/anchore/syft/syft/cataloging"

const mavenBaseURL = "https://repo1.maven.org/maven2"

type ArchiveCatalogerConfig struct {
	cataloging.ArchiveSearchConfig `yaml:",inline" json:"" mapstructure:",squash"`
	UseNetwork                     bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	MavenBaseURL                   string `yaml:"maven-base-url" json:"maven-base-url" mapstructure:"maven-base-url"`
	MaxParentRecursiveDepth        int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
	SkipTestComponents             bool   `yaml:"no-test-components" json:"no-test-components" mapstructure:"no-test-components"`
}

func DefaultArchiveCatalogerConfig() ArchiveCatalogerConfig {
	return ArchiveCatalogerConfig{
		ArchiveSearchConfig:     cataloging.DefaultArchiveSearchConfig(),
		UseNetwork:              false,
		MavenBaseURL:            mavenBaseURL,
		MaxParentRecursiveDepth: 5,
	}
}

func (j ArchiveCatalogerConfig) WithUseNetwork(input bool) ArchiveCatalogerConfig {
	j.UseNetwork = input
	return j
}

func (j ArchiveCatalogerConfig) WithMavenBaseURL(input string) ArchiveCatalogerConfig {
	if input != "" {
		j.MavenBaseURL = input
	}
	return j
}

func (j ArchiveCatalogerConfig) WithSkipTestComponents(skipTestComponents bool) ArchiveCatalogerConfig {
	j.SkipTestComponents = skipTestComponents
	return j
}

func (j ArchiveCatalogerConfig) WithArchiveTraversal(
	search cataloging.ArchiveSearchConfig, maxDepth int,
) ArchiveCatalogerConfig {
	if maxDepth > 0 {
		j.MaxParentRecursiveDepth = maxDepth
	}
	j.ArchiveSearchConfig = search
	return j
}
