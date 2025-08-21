package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"

	"shixi-proj/internal/store"
)

type Scanner struct {
	dbType string
	addr   string
	user   string
	pass   string
	dsn    string
	dry    bool
}

func New(dbType, addr, user, pass, dsn string, dry bool) *Scanner {
	return &Scanner{dbType: dbType, addr: addr, user: user, pass: pass, dsn: dsn, dry: dry}
}

func (s *Scanner) FetchVersion(ctx context.Context) (string, store.TargetMeta, error) {
	// DEMO：--dry-run 返回模拟版本，方便不装驱动直接跑通。
	if s.dry {
		switch strings.ToLower(s.dbType) {
		case "mysql":
			return "8.0.33", store.TargetMeta{Vendor: "Oracle", Product: "MySQL", DBType: "mysql", Addr: s.addr}, nil
		case "postgres":
			return "14.9", store.TargetMeta{Vendor: "PostgreSQL", Product: "PostgreSQL", DBType: "postgres", Addr: s.addr}, nil
		case "mssql":
			return "15.0.2000.5", store.TargetMeta{Vendor: "Microsoft", Product: "SQL Server", DBType: "mssql", Addr: s.addr}, nil
		case "oracle":
			return "19c", store.TargetMeta{Vendor: "Oracle", Product: "Database", DBType: "oracle", Addr: s.addr}, nil
		}
		return "unknown", store.TargetMeta{Vendor: "Unknown", Product: "Unknown", DBType: s.dbType, Addr: s.addr}, nil
	}

	// 实际连目标数据库读取版本
	switch strings.ToLower(s.dbType) {
	case "mysql":
		return fetchMySQL(ctx, s)
	case "postgres", "postgresql":
		return fetchPostgres(ctx, s)
	case "mssql", "sqlserver":
		return fetchMSSQL(ctx, s)
	case "oracle":
		return fetchOracle(ctx, s)
	default:
		return "", store.TargetMeta{}, fmt.Errorf("unsupported db type: %s", s.dbType)
	}
}

// ---- concrete drivers ----

func fetchMySQL(ctx context.Context, s *Scanner) (string, store.TargetMeta, error) {
	dsn := s.dsn
	if dsn == "" {
		if s.addr == "" {
			s.addr = "127.0.0.1:3306"
		}
		dsn = fmt.Sprintf("%s:%s@tcp(%s)/?timeout=5s&readTimeout=5s&writeTimeout=5s", s.user, s.pass, s.addr)
	}
	db, err := openWithDriver(ctx, "mysql", dsn)
	if err != nil {
		return "", store.TargetMeta{}, err
	}
	defer db.Close()
	var ver string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&ver); err != nil {
		return "", store.TargetMeta{}, err
	}
	return ver, store.TargetMeta{Vendor: "Oracle", Product: "MySQL", DBType: "mysql", Addr: s.addr}, nil
}

func fetchPostgres(ctx context.Context, s *Scanner) (string, store.TargetMeta, error) {
	dsn := s.dsn
	if dsn == "" {
		host, port := splitHostPortDefault(s.addr, 5432)
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable", s.user, s.pass, host, port)
	}
	db, err := openWithDriver(ctx, "postgres", dsn)
	if err != nil {
		return "", store.TargetMeta{}, err
	}
	defer db.Close()
	var ver string
	if err := db.QueryRowContext(ctx, "SELECT version()").Scan(&ver); err != nil {
		return "", store.TargetMeta{}, err
	}
	ver = extractFirstVersionNumber(ver)
	return ver, store.TargetMeta{Vendor: "PostgreSQL", Product: "PostgreSQL", DBType: "postgres", Addr: s.addr}, nil
}

func fetchMSSQL(ctx context.Context, s *Scanner) (string, store.TargetMeta, error) {
	dsn := s.dsn
	if dsn == "" {
		host, port := splitHostPortDefault(s.addr, 1433)
		// SQL Server connection string
		dsn = fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=master", s.user, s.pass, host, port)
	}
	db, err := openWithDriver(ctx, "sqlserver", dsn)
	if err != nil {
		return "", store.TargetMeta{}, err
	}
	defer db.Close()
	var ver string
	if err := db.QueryRowContext(ctx, "SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128))").Scan(&ver); err != nil {
		return "", store.TargetMeta{}, err
	}
	return ver, store.TargetMeta{Vendor: "Microsoft", Product: "SQL Server", DBType: "mssql", Addr: s.addr}, nil
}

func fetchOracle(ctx context.Context, s *Scanner) (string, store.TargetMeta, error) {
	dsn := s.dsn
	if dsn == "" {
		if s.addr == "" {
			s.addr = "127.0.0.1:1521"
		}
		// godror easy connect string: user/password@host:port/service
		dsn = fmt.Sprintf("%s/%s@%s/%s", s.user, s.pass, s.addr, "XE")
	}
	db, err := openWithDriver(ctx, "godror", dsn)
	if err != nil {
		return "", store.TargetMeta{}, err
	}
	defer db.Close()
	var banner string
	if err := db.QueryRowContext(ctx, "SELECT banner FROM v$version WHERE banner LIKE 'Oracle%' FETCH FIRST 1 ROWS ONLY").Scan(&banner); err != nil {
		return "", store.TargetMeta{}, err
	}
	ver := extractFirstVersionNumber(banner)
	return ver, store.TargetMeta{Vendor: "Oracle", Product: "Database", DBType: "oracle", Addr: s.addr}, nil
}

// helpers
func openWithDriver(ctx context.Context, driver, dsn string) (*sql.DB, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func splitHostPortDefault(addr string, defPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, defPort
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if port == 0 {
		port = defPort
	}
	return host, port
}

func extractFirstVersionNumber(s string) string {
	parts := strings.Fields(s)
	for _, p := range parts {
		for i := 0; i < len(p); i++ {
			if p[i] >= '0' && p[i] <= '9' {
				return p
			}
		}
	}
	return s
}
