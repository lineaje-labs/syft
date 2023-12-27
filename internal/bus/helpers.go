package bus

import (
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/event"
	"github.com/lineaje-labs/syft/internal/redact"
)

func Exit() {
	Publish(clio.ExitEvent(false))
}

func ExitWithInterrupt() {
	Publish(clio.ExitEvent(true))
}

func Report(report string) {
	if len(report) == 0 {
		return
	}
	report = redact.Apply(report)
	Publish(partybus.Event{
		Type:  event.CLIReport,
		Value: report,
	})
}

func Notify(message string) {
	Publish(partybus.Event{
		Type:  event.CLINotification,
		Value: message,
	})
}
