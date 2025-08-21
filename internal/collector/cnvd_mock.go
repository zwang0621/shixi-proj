package collector

import (
	"context"
	"time"

	"shixi-proj/internal/store"
)

// CNVD web collector placeholder; replace with real API/scraper later
type CNVDCollector struct{}

func NewCNVDCollector() *CNVDCollector { return &CNVDCollector{} }

func (c *CNVDCollector) Collect(ctx context.Context, st *store.Store, since string) error {
	now := time.Now()
	_ = st.InsertVuln(ctx, store.VulnRecord{Source: "CNVD", Vendor: "Oracle", Product: "MySQL", VersionStart: "8.0.0", VersionEnd: "8.0.33", VulnID: "CNVD-DEMO", VulnName: "Demo", Description: "Demo CNVD entry", Severity: "MEDIUM", ScanDate: &now})
	return nil
}
