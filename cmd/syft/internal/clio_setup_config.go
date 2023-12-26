package internal

import (
	"io"
	"os"
	"reflect"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope"
	ui2 "github.com/anchore/syft/cmd/syft/cli/ui"
	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/redact"
)

func AppClioSetupConfig(id clio.Identification, out io.Writer) *clio.SetupConfig {
	clioCfg := clio.NewSetupConfig(id).
		WithGlobalConfigFlag().   // add persistent -c <path> for reading an application config from
		WithGlobalLoggingFlags(). // add persistent -v and -q flags tied to the logging config
		WithConfigInRootHelp().   // --help on the root command renders the full application config in the help text
		WithUIConstructor(
			// select a UI based on the logging configuration and state of stdin (if stdin is a tty)
			func(cfg clio.Config) ([]clio.UI, error) {
				noUI := ui.None(out, cfg.Log.Quiet)
				if !cfg.Log.AllowUI(os.Stdin) || cfg.Log.Quiet {
					return []clio.UI{noUI}, nil
				}

				return []clio.UI{
					ui.New(out, cfg.Log.Quiet,
						ui2.New(ui2.DefaultHandlerConfig()),
					),
					noUI,
				}, nil
			},
		).
		WithInitializers(
			func(state *clio.State) error {
				// clio is setting up and providing the bus, redact store, and logger to the application. Once loaded,
				// we can hoist them into the internal packages for global use.
				stereoscope.SetBus(state.Bus)
				bus.Set(state.Bus)

				redact.Set(state.RedactStore)

				log.Set(state.Logger)
				stereoscope.SetLogger(state.Logger)
				return nil
			},
		).
		WithPostRuns(func(state *clio.State, _ error) {
			// Do not run cleanup if it is disabled.
			if !isCleanupDisabled(state) {
				stereoscope.Cleanup()
			}
		})
	return clioCfg
}

// isCleanupDisabled checks if the cleanup option is disabled in the provided state object.
// This option is unexported so reflection is used to get the value set.
func isCleanupDisabled(state *clio.State) bool {
	var cleanupDisabled bool
	for _, configObj := range state.Config.FromCommands {
		if reflect.TypeOf(configObj).String() == "*commands.scanOptions" { // Cleanup option is part of packageOptions
			configObjData := reflect.ValueOf(configObj)
			if configObjData.Kind() == reflect.Ptr && configObjData.Elem().Kind() == reflect.Struct {
				configObjData = configObjData.Elem()
			} else {
				continue
			}
			for i := 0; i < configObjData.NumField(); i++ {
				field := configObjData.Field(i)
				if field.Type().Name() == "Catalog" { // Cleanup option is part of Catalog
					catalogData, ok := field.Interface().(options.Catalog)
					if ok {
						cleanupDisabled = catalogData.CleanupDisabled
					}
					break
				}
			}
			break
		}
	}
	return cleanupDisabled
}
