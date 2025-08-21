package result

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"shixi-proj/internal/store"

	"github.com/jung-kurt/gofpdf"
)

type Exporter struct{ st *store.Store }

func NewExporter(st *store.Store) *Exporter { return &Exporter{st: st} }

func (e *Exporter) Export(ctx context.Context, format string) ([]byte, error) {
	all, err := e.st.All(ctx)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(all, "", "  ")
	case "csv":
		var b strings.Builder
		w := csv.NewWriter(&b)
		_ = w.Write([]string{"id", "source", "vendor", "product", "version_start", "version_end", "version_number", "vuln_id", "vuln_name", "severity", "final_score"})
		for _, v := range all {
			fs := ""
			if v.FinalScore != nil {
				fs = fmt.Sprintf("%.2f", *v.FinalScore)
			}
			_ = w.Write([]string{fmt.Sprint(v.ID), v.Source, v.Vendor, v.Product, v.VersionStart, v.VersionEnd, v.VersionNumber, v.VulnID, v.VulnName, v.Severity, fs})
		}
		w.Flush()
		return []byte(b.String()), nil
	case "pdf":
		pdf := gofpdf.New("P", "mm", "A4", "")
		pdf.AddPage()
		pdf.SetFont("Arial", "B", 14)
		pdf.Cell(40, 10, "Vulnerability Scan Report")
		pdf.Ln(12)
		pdf.SetFont("Arial", "", 10)
		for _, v := range all {
			fs := 0.0
			if v.FinalScore != nil {
				fs = *v.FinalScore
			}
			line := fmt.Sprintf("[%s] %s %s %s (%s-%s) score=%.2f", v.Source, v.Vendor, v.Product, v.VulnID, v.VersionStart, v.VersionEnd, fs)
			pdf.MultiCell(0, 6, line, "0", "L", false)
		}
		var buf strings.Builder
		if err := pdf.Output(io.Writer(&buf)); err != nil {
			return nil, err
		}
		return []byte(buf.String()), nil
	default:
		return nil, fmt.Errorf("unknown format %s", format)
	}
}
