package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Store struct {
	db *sql.DB
}

func NewDefaultStore() (*Store, error) {
	dsn := os.Getenv("STORE_DSN")
	if dsn == "" {
		dsn = "root:123456@tcp(127.0.0.1:3306)/scanner?parseTime=true"
	}
	return New(dsn)
}

func New(dsn string) (*Store, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	// create tables (single statements)
	createVuln := `CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    source VARCHAR(20),
    vendor_name VARCHAR(100),
    product_name VARCHAR(200),
    version_start VARCHAR(50),
    version_end VARCHAR(50),
    version_number VARCHAR(50),
    version_start_key BIGINT NULL,
    version_end_key BIGINT NULL,
    version_number_key BIGINT NULL,
    vuln_id VARCHAR(50),
    vuln_name VARCHAR(200),
    vuln_description TEXT,
    cvss_score FLOAT,
    cnvd_score FLOAT,
    aliyun_score FLOAT,
    score_final FLOAT,
    severity VARCHAR(20),
    patch_info TEXT,
    scan_date TIMESTAMP
)`
	if _, err := s.db.ExecContext(ctx, createVuln); err != nil {
		return err
	}
	createTasks := `CREATE TABLE IF NOT EXISTS tasks (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    db_type VARCHAR(20) NOT NULL,
    addr VARCHAR(200) NOT NULL,
    user_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending',
    UNIQUE KEY uniq_task (db_type, addr)
)`
	if _, err := s.db.ExecContext(ctx, createTasks); err != nil {
		return err
	}
	// indexes: MySQL lacks IF NOT EXISTS for CREATE INDEX in some versions; ignore duplicates
	_ = s.execIgnoreDupIndex(ctx, `CREATE INDEX idx_vendor_product ON vulnerability_scans(vendor_name, product_name)`)
	_ = s.execIgnoreDupIndex(ctx, `CREATE INDEX idx_version_keys ON vulnerability_scans(version_start_key, version_end_key, version_number_key)`)
	_ = s.execIgnoreDupIndex(ctx, `CREATE UNIQUE INDEX uniq_vuln ON vulnerability_scans(source, vendor_name, product_name, version_start, version_end, version_number, vuln_id)`)
	return nil
}

func (s *Store) execIgnoreDupIndex(ctx context.Context, ddl string) error {
	_, err := s.db.ExecContext(ctx, ddl)
	if err != nil {
		e := err.Error()
		if strings.Contains(e, "Duplicate key name") || strings.Contains(e, "1061") {
			return nil
		}
	}
	return err
}

// ---- Data types ----
type TargetMeta struct {
	Vendor  string
	Product string
	DBType  string
	Addr    string
}

type VulnRecord struct {
	ID            int64
	Source        string
	Vendor        string
	Product       string
	VersionStart  string
	VersionEnd    string
	VersionNumber string
	VulnID        string
	VulnName      string
	Description   string
	CVSS          *float64
	CNVD          *float64
	Aliyun        *float64
	FinalScore    *float64
	Severity      string
	PatchInfo     string
	ScanDate      *time.Time
}

func (s *Store) InsertVuln(ctx context.Context, v VulnRecord) error {
	vsKey := versionKey(v.VersionStart)
	veKey := versionKey(v.VersionEnd)
	vnKey := versionKey(v.VersionNumber)
	_, err := s.db.ExecContext(ctx, `INSERT INTO vulnerability_scans
    (source, vendor_name, product_name, version_start, version_end, version_number, version_start_key, version_end_key, version_number_key, vuln_id, vuln_name, vuln_description, cvss_score, cnvd_score, aliyun_score, score_final, severity, patch_info, scan_date)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ON DUPLICATE KEY UPDATE
      vuln_name=VALUES(vuln_name),
      vuln_description=VALUES(vuln_description),
      cvss_score=VALUES(cvss_score),
      cnvd_score=VALUES(cnvd_score),
      aliyun_score=VALUES(aliyun_score),
      score_final=VALUES(score_final),
      severity=VALUES(severity),
      patch_info=VALUES(patch_info),
      scan_date=VALUES(scan_date)`,
		v.Source, v.Vendor, v.Product, v.VersionStart, v.VersionEnd, v.VersionNumber, vsKey, veKey, vnKey, v.VulnID, v.VulnName, v.Description, v.CVSS, v.CNVD, v.Aliyun, v.FinalScore, v.Severity, v.PatchInfo, v.ScanDate)
	return err
}

func (s *Store) QueryVulnsByRange(ctx context.Context, vendor, product, version string) ([]VulnRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, source, vendor_name, product_name, version_start, version_end, version_number, vuln_id, vuln_name, vuln_description, cvss_score, cnvd_score, aliyun_score, score_final, severity, patch_info, scan_date
    FROM vulnerability_scans
    WHERE vendor_name=? AND product_name=?`, vendor, product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []VulnRecord
	for rows.Next() {
		var v VulnRecord
		var scanDate sql.NullTime
		if err := rows.Scan(&v.ID, &v.Source, &v.Vendor, &v.Product, &v.VersionStart, &v.VersionEnd, &v.VersionNumber, &v.VulnID, &v.VulnName, &v.Description, &v.CVSS, &v.CNVD, &v.Aliyun, &v.FinalScore, &v.Severity, &v.PatchInfo, &scanDate); err != nil {
			return nil, err
		}
		if scanDate.Valid {
			t := scanDate.Time
			v.ScanDate = &t
		}
		out = append(out, v)
	}
	return out, nil
}

// SQL-side matching using normalized keys
func (s *Store) QueryVulnsMatch(ctx context.Context, vendor, product, version string) ([]VulnRecord, error) {
	vKey := versionKey(version)
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, source, vendor_name, product_name, version_start, version_end, version_number,
               vuln_id, vuln_name, vuln_description, cvss_score, cnvd_score, aliyun_score,
               score_final, severity, patch_info, scan_date
        FROM vulnerability_scans
        WHERE vendor_name=? AND product_name=? AND (
            (version_number_key IS NOT NULL AND version_number_key = ?) OR
            (
                (version_start_key IS NULL OR version_start_key <= ?) AND
                (version_end_key IS NULL OR version_end_key >= ?)
            )
        )
    `, vendor, product, vKey, vKey, vKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnRecord
	for rows.Next() {
		var v VulnRecord
		var scanDate sql.NullTime
		if err := rows.Scan(&v.ID, &v.Source, &v.Vendor, &v.Product, &v.VersionStart, &v.VersionEnd, &v.VersionNumber, &v.VulnID, &v.VulnName, &v.Description, &v.CVSS, &v.CNVD, &v.Aliyun, &v.FinalScore, &v.Severity, &v.PatchInfo, &scanDate); err != nil {
			return nil, err
		}
		if scanDate.Valid {
			t := scanDate.Time
			v.ScanDate = &t
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Store) SaveScanResult(ctx context.Context, meta TargetMeta, version string, vulns []VulnRecord, when time.Time) (int64, error) {
	if len(vulns) == 0 {
		v := VulnRecord{
			Source:        "scan",
			Vendor:        meta.Vendor,
			Product:       meta.Product,
			VersionNumber: version,
			VulnID:        fmt.Sprintf("SCAN-%d", when.Unix()),
			VulnName:      "No matching vulnerabilities",
			ScanDate:      &when,
		}
		if err := s.InsertVuln(ctx, v); err != nil {
			return 0, err
		}
		return 0, nil
	}
	for _, v := range vulns {
		vv := v
		vv.Source = "scan"
		vv.VersionNumber = version
		vv.ScanDate = &when
		if err := s.InsertVuln(ctx, vv); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func (s *Store) All(ctx context.Context) ([]VulnRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, source, vendor_name, product_name, version_start, version_end, version_number, 
               vuln_id, vuln_name, vuln_description, cvss_score, cnvd_score, aliyun_score, 
               score_final, severity, patch_info, scan_date
        FROM vulnerability_scans
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []VulnRecord
	for rows.Next() {
		var v VulnRecord
		var scanDate sql.NullTime
		if err := rows.Scan(
			&v.ID, &v.Source, &v.Vendor, &v.Product,
			&v.VersionStart, &v.VersionEnd, &v.VersionNumber,
			&v.VulnID, &v.VulnName, &v.Description,
			&v.CVSS, &v.CNVD, &v.Aliyun, &v.FinalScore,
			&v.Severity, &v.PatchInfo, &scanDate,
		); err != nil {
			return nil, err
		}
		if scanDate.Valid {
			t := scanDate.Time
			v.ScanDate = &t
		}
		out = append(out, v)
	}
	return out, nil
}

var ErrNotFound = errors.New("not found")

// ---- helpers ----
var digitRe = regexp.MustCompile(`\d+`)

func versionKey(s string) *int64 {
	if s == "" {
		return nil
	}
	nums := digitRe.FindAllString(s, -1)
	if len(nums) == 0 {
		return nil
	}
	var maj, min, patch int
	maj = parseIntSafe(nums, 0)
	min = parseIntSafe(nums, 1)
	patch = parseIntSafe(nums, 2)
	key := int64(maj)*1_000_000 + int64(min)*1_000 + int64(patch)
	return &key
}

func parseIntSafe(nums []string, idx int) int {
	if idx >= len(nums) {
		return 0
	}
	n, _ := strconv.Atoi(nums[idx])
	return n
}
