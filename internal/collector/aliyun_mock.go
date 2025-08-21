package collector

import (
	"context"
	"time"

	"shixi-proj/internal/store"
)

type AliyunCollector struct{}

func NewAliyunCollector() *AliyunCollector { return &AliyunCollector{} }

func (a *AliyunCollector) Collect(ctx context.Context, st *store.Store, since string) error {
	// Placeholder: no external dependency; replace with real API/scraper later
	now := time.Now()
	_ = st.InsertVuln(ctx, store.VulnRecord{Source: "ALIYUN", Vendor: "PostgreSQL", Product: "PostgreSQL", VersionStart: "14.0", VersionEnd: "14.9", VulnID: "ALIYUN-DEMO", VulnName: "Demo", Description: "Demo Aliyun entry", Severity: "MEDIUM", ScanDate: &now})
	return nil
}
