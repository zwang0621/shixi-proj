package matcher

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"shixi-proj/internal/store"
)

type Engine struct{ st *store.Store }

func New(st *store.Store) *Engine { return &Engine{st: st} }

// 简单版本：先按 vendor/product 拉全集，再在内存里做版本命中（区间或等值）。
// 生产环境建议把版本拆字段并下沉到 SQL + 索引。
func (e *Engine) Match(ctx context.Context, vendor, product, version string) ([]store.VulnRecord, error) {
	// 尝试使用 SQL 侧归一化键过滤
	rows, err := e.st.QueryVulnsMatch(ctx, vendor, product, version)
	if err != nil {
		// 回退到全集 + 内存过滤
		rows, err = e.st.QueryVulnsByRange(ctx, vendor, product, version)
		if err != nil {
			return nil, err
		}
	}
	var out []store.VulnRecord
	for _, v := range rows {
		// 如果记录只给了具体 version_number，则按等值命中
		if v.VersionNumber != "" {
			if equalVersion(version, v.VersionNumber) {
				out = append(out, v)
			}
			continue
		}
		// 区间比较：version_start <= version <= version_end（缺省端开放）
		if (v.VersionStart == "" || cmpVersion(version, v.VersionStart) >= 0) &&
			(v.VersionEnd == "" || cmpVersion(version, v.VersionEnd) <= 0) {
			out = append(out, v)
		}
	}
	// 可在此处统一计算 FinalScore（例如权重：CVE:0.6, CNVD:0.25, Aliyun:0.15）
	for i := range out {
		out[i].FinalScore = calcWeighted(out[i].CVSS, out[i].CNVD, out[i].Aliyun)
	}
	return out, nil
}

func calcWeighted(cve, cnvd, aliyun *float64) *float64 {
	// 默认权重；若要可配置，可从环境变量或配置文件读取
	wCVE, wCNVD, wALY := 0.6, 0.25, 0.15
	var s, w float64
	if cve != nil {
		s += *cve * wCVE
		w += wCVE
	}
	if cnvd != nil {
		s += *cnvd * wCNVD
		w += wCNVD
	}
	if aliyun != nil {
		s += *aliyun * wALY
		w += wALY
	}
	if w == 0 {
		return nil
	}
	v := s / w
	return &v
}

// -------- 版本比较（轻量实现） --------
// 将 "19c" "8.0.33" "15.0.2000.5" 等尽量数值化比较，非数字落到次级。

var numRe = regexp.MustCompile(`\d+`)

func tokenizeVersion(s string) []int {
	// 提取所有数字片段
	nums := numRe.FindAllString(s, -1)
	out := make([]int, 0, len(nums))
	for _, n := range nums {
		x, _ := strconv.Atoi(n)
		out = append(out, x)
	}
	return out
}

func cmpVersion(a, b string) int {
	aa := strings.TrimSpace(a)
	bb := strings.TrimSpace(b)
	ta := tokenizeVersion(aa)
	tb := tokenizeVersion(bb)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		var xa, xb int
		if i < len(ta) {
			xa = ta[i]
		}
		if i < len(tb) {
			xb = tb[i]
		}
		if xa > xb {
			return 1
		}
		if xa < xb {
			return -1
		}
	}
	// 数字完全相等时，用原始字符串长度作为次序（更具体的版本更大）
	if len(aa) > len(bb) {
		return 1
	}
	if len(aa) < len(bb) {
		return -1
	}
	return 0
}

func equalVersion(a, b string) bool { return cmpVersion(a, b) == 0 }
