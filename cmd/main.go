package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"shixi-proj/internal/collector"
	"shixi-proj/internal/matcher"
	"shixi-proj/internal/result"
	"shixi-proj/internal/scanner"
	"shixi-proj/internal/server"
	"shixi-proj/internal/store"
	"shixi-proj/internal/task"
)

func main() {
	mode := flag.String("mode", "help", "help|collect|scan|export|tasks|server")
	source := flag.String("source", "cve", "cve|cnvd|aliyun")
	since := flag.String("since", "", "collect since (YYYY-MM-DD)")
	db := flag.String("db", "mysql", "mysql|postgres|mssql|oracle")
	addr := flag.String("addr", "", "target db address host:port")
	user := flag.String("user", "", "target db user")
	pass := flag.String("password", "", "target db password")
	dsn := flag.String("dsn", "", "optional DSN (overrides db/user/pass/addr)")
	dry := flag.Bool("dry-run", true, "dry-run without real DB connection")
	format := flag.String("format", "json", "export format: json|csv|pdf")
	out := flag.String("out", "scan_result.json", "export output path")
	httpAddr := flag.String("http-addr", ":8080", "http listen address (server mode)")
	flag.Parse()

	ctx := context.Background()

	st, err := store.NewDefaultStore()
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	switch *mode {
	case "collect":
		var c collector.Collector
		switch *source {
		case "cve":
			c = collector.NewCVECollector()
		case "cnvd":
			c = collector.NewCNVDCollector()
		case "aliyun":
			c = collector.NewAliyunCollector()
		default:
			log.Fatalf("unknown source %s", *source)
		}
		if err := c.Collect(ctx, st, *since); err != nil {
			log.Fatalf("collect failed: %v", err)
		}
		fmt.Println("collect done")

	case "scan":
		sc := scanner.New(*db, *addr, *user, *pass, *dsn, *dry)
		ver, meta, err := sc.FetchVersion(ctx)
		if err != nil {
			log.Fatalf("fetch version: %v", err)
		}
		fmt.Printf("Detected: vendor=%s product=%s version=%s\n", meta.Vendor, meta.Product, ver)

		m := matcher.New(st)
		vulns, err := m.Match(ctx, meta.Vendor, meta.Product, ver)
		if err != nil {
			log.Fatalf("match: %v", err)
		}
		recID, err := st.SaveScanResult(ctx, meta, ver, vulns, time.Now())
		if err != nil {
			log.Fatalf("save result: %v", err)
		}
		fmt.Printf("Scan saved: record_id=%d, vulns=%d\n", recID, len(vulns))

	case "export":
		ex := result.NewExporter(st)
		b, err := ex.Export(ctx, *format)
		if err != nil {
			log.Fatalf("export: %v", err)
		}
		if err := os.WriteFile(*out, b, 0644); err != nil {
			log.Fatalf("write: %v", err)
		}
		fmt.Printf("Exported -> %s\n", *out)

	case "tasks":
		mgr := task.NewManager(st)
		fmt.Println("Tasks:", mgr.DebugList())

	case "server":
		srv := server.New(st)
		if err := srv.ListenAndServe(ctx, *httpAddr); err != nil {
			log.Fatalf("server: %v", err)
		}

	default:
		fmt.Println("Usage examples:")
		fmt.Println("  go run ./cmd --mode collect --source cve --since 2025-01-01")
		fmt.Println("  go run ./cmd --mode scan --db mysql --addr 127.0.0.1:3306 --user root --password 123456 --dry-run")
		fmt.Println("  go run ./cmd --mode export --format json --out ./scan_result.json")
	}
}
