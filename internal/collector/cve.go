package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"shixi-proj/internal/store"
)

type CVECollector struct {
	Base string
	Key  string
}

func NewCVECollector() *CVECollector {
	return &CVECollector{Base: "https://services.nvd.nist.gov/rest/json/cves/2.0"}
}

// 仅做最小可用解析：筛选与常见数据库相关的 CPE，抽取版本范围、分数、描述
func (c *CVECollector) Collect(ctx context.Context, st *store.Store, since string) error {
	// 关键词与 CPE 过滤，降低无关数据
	keywords := []string{"mysql", "postgresql", "sql server", "oracle"}
	cpes := []string{
		"cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
	}
	pageSize := 200
	startIndex := 0
	now := time.Now()
	for {
		params := url.Values{}
		params.Set("resultsPerPage", fmt.Sprint(pageSize))
		params.Set("startIndex", fmt.Sprint(startIndex))
		params.Set("keywordSearch", strings.Join(keywords, ","))
		if since != "" {
			params.Set("pubStartDate", since+"T00:00:00.000")
		}
		endpoint := c.Base + "?" + params.Encode()
		for _, cpe := range cpes {
			endpoint += "&cpeName=" + url.QueryEscape(cpe)
		}
		body, err := c.doGETWithRetry(ctx, endpoint, 3)
		if err != nil {
			// 容忍远端波动：停止采集但不报错
			return nil
		}
		if len(body) == 0 {
			break
		}
		var root map[string]any
		if err := json.Unmarshal(body, &root); err != nil {
			// 容忍无效 JSON：停止采集
			break
		}
		vulns, _ := root["vulnerabilities"].([]any)
		if len(vulns) == 0 {
			break
		}
		for _, vv := range vulns {
			obj, ok := vv.(map[string]any)
			if !ok {
				continue
			}
			cve := getMap(obj, "cve")
			cveID := getString(cve, "id")
			if cveID == "" {
				continue
			}
			desc := pickDescription(getSlice(getMap(cve, "descriptions"), ""))
			score := extractScore(cve)
			cfg := getMap(cve, "configurations")
			nodes := getSlice(cfg, "nodes")
			for _, n := range nodes {
				node, ok := n.(map[string]any)
				if !ok {
					continue
				}
				matches := getSlice(node, "cpeMatch")
				for _, mm := range matches {
					m, ok := mm.(map[string]any)
					if !ok {
						continue
					}
					criteria := getString(m, "criteria")
					vulnerable, _ := m["vulnerable"].(bool)
					if !vulnerable || criteria == "" {
						continue
					}
					vendor, product, version := parseCPE(criteria)
					if !isDBProduct(vendor, product) {
						continue
					}
					vsInc := getString(m, "versionStartIncluding")
					vsExc := getString(m, "versionStartExcluding")
					veInc := getString(m, "versionEndIncluding")
					veExc := getString(m, "versionEndExcluding")
					start := firstNonEmpty(vsInc, vsExc)
					end := firstNonEmpty(veInc, veExc)
					sev := "UNKNOWN"
					if score != nil {
						if *score >= 9 {
							sev = "CRITICAL"
						} else if *score >= 7 {
							sev = "HIGH"
						} else if *score >= 4 {
							sev = "MEDIUM"
						} else {
							sev = "LOW"
						}
					}
					rec := store.VulnRecord{
						Source:       "CVE",
						Vendor:       vendorNameCanonical(vendor, product),
						Product:      productNameCanonical(vendor, product),
						VersionStart: start,
						VersionEnd:   end,
						VulnID:       cveID,
						VulnName:     cveID,
						Description:  desc,
						CVSS:         score,
						Severity:     sev,
						ScanDate:     &now,
					}
					_ = st.InsertVuln(ctx, rec)
					if version != "" {
						rec.VersionStart = ""
						rec.VersionEnd = ""
						rec.VersionNumber = version
						_ = st.InsertVuln(ctx, rec)
					}
				}
			}
		}
		startIndex += pageSize
		time.Sleep(350 * time.Millisecond)
	}
	return nil
}

func (c *CVECollector) doGETWithRetry(ctx context.Context, urlStr string, maxRetry int) ([]byte, error) {
	var lastErr error
	for i := 0; i < maxRetry; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if c.Key != "" {
			req.Header.Set("apiKey", c.Key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			time.Sleep(time.Duration(400*(i+1)) * time.Millisecond)
			continue
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
			continue
		}
		return b, nil
	}
	if lastErr == nil {
		lastErr = errors.New("unknown error")
	}
	return nil, lastErr
}

func getMap(m map[string]any, k string) map[string]any {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}
func getSlice(m map[string]any, k string) []any {
	if v, ok := m[k].([]any); ok {
		return v
	}
	return nil
}
func getString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}
func pickDescription(descs []any) string {
	for _, d := range descs {
		row := d.(map[string]any)
		lang := strings.ToLower(getString(row, "lang"))
		if lang == "en" {
			return getString(row, "value")
		}
	}
	// 兜底取第一条
	if len(descs) > 0 {
		row := descs[0].(map[string]any)
		return getString(row, "value")
	}
	return ""
}
func extractScore(cve map[string]any) *float64 {
	metrics := getMap(cve, "metrics")
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		arr := getSlice(metrics, key)
		if len(arr) == 0 {
			continue
		}
		first := arr[0].(map[string]any)
		cvssData := getMap(first, "cvssData")
		score, ok := cvssData["baseScore"].(float64)
		if ok {
			return &score
		}
	}
	return nil
}

// 解析 cpe:2.3:a:vendor:product:version:...
func parseCPE(c string) (vendor, product, version string) {
	// 简化：不完整 CPE 也不强求严格解析
	parts := strings.Split(c, ":")
	if len(parts) >= 5 {
		vendor = parts[3]
		product = parts[4]
		if len(parts) >= 6 {
			version = parts[5]
		}
	}
	return
}

func isDBProduct(vendor, product string) bool {
	v := strings.ToLower(vendor)
	p := strings.ToLower(product)
	if v == "oracle" && (p == "mysql" || p == "database") {
		return true
	}
	if v == "postgresql" && p == "postgresql" {
		return true
	}
	if v == "microsoft" && (strings.Contains(p, "sql") || p == "sql_server") {
		return true
	}
	// 其他数据库可在此拓展
	return false
}

// 让最终插表时更友好
func vendorNameCanonical(vendor, product string) string {
	v := strings.ToLower(vendor)
	if v == "postgresql" {
		return "PostgreSQL"
	}
	if v == "microsoft" {
		return "Microsoft"
	}
	if v == "oracle" {
		// MySQL 归到 Oracle 也是合理的
		return "Oracle"
	}
	return strings.Title(vendor)
}
func productNameCanonical(vendor, product string) string {
	v := strings.ToLower(vendor)
	p := strings.ToLower(product)
	if v == "postgresql" {
		return "PostgreSQL"
	}
	if v == "microsoft" {
		return "SQL Server"
	}
	if v == "oracle" {
		if p == "mysql" {
			return "MySQL"
		}
		if p == "database" {
			return "Database"
		}
	}
	return strings.Title(product)
}
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
