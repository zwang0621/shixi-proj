package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"shixi-proj/internal/collector"
	"shixi-proj/internal/matcher"
	"shixi-proj/internal/result"
	"shixi-proj/internal/scanner"
	"shixi-proj/internal/store"
)

type Server struct {
	store *store.Store
}

func New(st *store.Store) *Server { return &Server{store: st} }

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/vulns", s.handleListVulns)
	mux.HandleFunc("/export", s.handleExport)
	mux.HandleFunc("/scan", s.handleScan)
	mux.HandleFunc("/collect", s.handleCollect)

	server := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	return server.ListenAndServe()
}

func (s *Server) handleListVulns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	all, err := s.store.All(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, all)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	ex := result.NewExporter(s.store)
	b, err := ex.Export(ctx, format)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
	}
	if format == "pdf" {
		w.Header().Set("Content-Type", "application/pdf")
	}
	_, _ = w.Write(b)
}

type scanReq struct {
	DBType string `json:"db_type"`
	Addr   string `json:"addr"`
	User   string `json:"user"`
	Pass   string `json:"password"`
	DSN    string `json:"dsn"`
	Dry    bool   `json:"dry_run"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req scanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sc := scanner.New(req.DBType, req.Addr, req.User, req.Pass, req.DSN, req.Dry)
	ctx := r.Context()
	ver, meta, err := sc.FetchVersion(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	m := matcher.New(s.store)
	vulns, err := m.Match(ctx, meta.Vendor, meta.Product, ver)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_, _ = s.store.SaveScanResult(ctx, meta, ver, vulns, time.Now())
	writeJSON(w, map[string]any{"version": ver, "meta": meta, "vulns": vulns})
}

func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	source := r.URL.Query().Get("source")
	since := r.URL.Query().Get("since")
	var c collector.Collector
	switch source {
	case "cve":
		c = collector.NewCVECollector()
	case "cnvd":
		c = collector.NewCNVDCollector()
	case "aliyun":
		c = collector.NewAliyunCollector()
	default:
		writeErr(w, http.StatusBadRequest, errStr("unknown source"))
		return
	}
	if err := c.Collect(r.Context(), s.store, since); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

type errStr string

func (e errStr) Error() string { return string(e) }
