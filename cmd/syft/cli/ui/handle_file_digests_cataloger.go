package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
	"github.com/lineaje-labs/syft/internal/log"
)

func (m *Handler) handleFileDigestsCatalogerStarted(e partybus.Event) []tea.Model {
	prog, err := syftEventParsers.ParseFileDigestsCatalogingStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil
	}

	tsk := m.newTaskProgress(
		taskprogress.Title{
			Default: "Catalog file digests",
			Running: "Cataloging file digests",
			Success: "Cataloged file digests",
		}, taskprogress.WithStagedProgressable(prog),
	)

	return []tea.Model{tsk}
}
