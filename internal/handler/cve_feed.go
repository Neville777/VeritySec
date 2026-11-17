package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type CVEFeedHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewCVEFeedHandler(db *database.DB, logger *zap.Logger) *CVEFeedHandler {
	h := &CVEFeedHandler{db: db, logger: logger}
	h.migrateSchema()
	return h
}

func (h *CVEFeedHandler) migrateSchema() {
	cols := []struct{ name, def string }{
		{"cwe_ids", "TEXT NOT NULL DEFAULT ''"},
		{"category", "TEXT NOT NULL DEFAULT 'other'"},
		{"affected_vendor", "TEXT NOT NULL DEFAULT ''"},
		{"affected_product", "TEXT NOT NULL DEFAULT ''"},
		{"affected_versions", "TEXT NOT NULL DEFAULT ''"},
		{"cpe_json", "TEXT NOT NULL DEFAULT '[]'"},
		{"ai_analysis", "TEXT NOT NULL DEFAULT ''"},
	}
	for _, c := range cols {
		h.db.Exec("ALTER TABLE cve_cache ADD COLUMN " + c.name + " " + c.def)
	}
	h.db.Exec("CREATE INDEX IF NOT EXISTS idx_cve_cache_category ON cve_cache(category)")
	h.db.Exec("CREATE INDEX IF NOT EXISTS idx_cve_cache_vendor ON cve_cache(affected_vendor)")
	h.db.Exec("CREATE INDEX IF NOT EXISTS idx_cve_cache_cvss ON cve_cache(cvss_score)")
}

func (h *CVEFeedHandler) SearchCVEs(c *gin.Context) {
	q := c.Query("q")
	category := c.Query("category")
	vendor := c.Query("vendor")
	limit := c.DefaultQuery("limit", "50")

	query := `SELECT cve_id, description, cvss_score, cvss_vector, epss_score, epss_percentile,
	                 kev_known_exploited, cwe_ids, category, affected_vendor, affected_product,
	                 affected_versions, published_at, fetched_at
	          FROM cve_cache WHERE 1=1`
	args := []interface{}{}

	if q != "" {
		query += " AND (cve_id LIKE ? OR description LIKE ? OR affected_product LIKE ?)"
		pat := "%" + q + "%"
		args = append(args, pat, pat, pat)
	}
	if category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}
	if vendor != "" {
		query += " AND affected_vendor LIKE ?"
		args = append(args, "%"+vendor+"%")
	}
	query += " ORDER BY COALESCE(cvss_score, 0) DESC LIMIT ?"
	args = append(args, limit)

	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var out []gin.H
	for rows.Next() {
		var cveID, desc, vector, cweIDs, cat, aVendor, aProduct, aVersions, pubAt, fetchAt string
		var cvss, epss, epssP *float64
		var kev int
		if err := rows.Scan(&cveID, &desc, &cvss, &vector, &epss, &epssP, &kev,
			&cweIDs, &cat, &aVendor, &aProduct, &aVersions, &pubAt, &fetchAt); err != nil {
			continue
		}
		out = append(out, gin.H{
			"cve_id": cveID, "description": desc, "cvss_score": cvss, "cvss_vector": vector,
			"epss_score": epss, "epss_percentile": epssP, "kev_known_exploited": kev > 0,
			"cwe_ids": cweIDs, "category": cat, "affected_vendor": aVendor,
			"affected_product": aProduct, "affected_versions": aVersions,
			"published_at": pubAt, "fetched_at": fetchAt,
		})
	}

	// Also return category counts for the filter sidebar
	catRows, err := h.db.Query(`SELECT category, COUNT(*) FROM cve_cache GROUP BY category ORDER BY COUNT(*) DESC`)
	var categories []gin.H
	if err == nil {
		defer catRows.Close()
		for catRows.Next() {
			var cat string
			var cnt int
			if catRows.Scan(&cat, &cnt) == nil {
				categories = append(categories, gin.H{"category": cat, "count": cnt})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"cves": out, "categories": categories})
}

// GetCVEDetail returns full details for a single CVE.
func (h *CVEFeedHandler) GetCVEDetail(c *gin.Context) {
	cveID := c.Param("cve_id")
	var desc, vector, cweIDs, cat, aVendor, aProduct, aVersions, cpeJSON, aiAnalysis, refsJSON, pubAt, modAt, fetchAt string
	var cvss, epss, epssP *float64
	var kev int

	err := h.db.QueryRow(`SELECT description, cvss_score, cvss_vector, epss_score, epss_percentile,
		kev_known_exploited, cwe_ids, category, affected_vendor, affected_product,
		affected_versions, cpe_json, ai_analysis, references_json, published_at, modified_at, fetched_at
		FROM cve_cache WHERE cve_id = ?`, cveID).Scan(
		&desc, &cvss, &vector, &epss, &epssP, &kev,
		&cweIDs, &cat, &aVendor, &aProduct, &aVersions,
		&cpeJSON, &aiAnalysis, &refsJSON, &pubAt, &modAt, &fetchAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CVE not found"})
		return
	}

	var refs []string
	json.Unmarshal([]byte(refsJSON), &refs)
	var cpes []interface{}
	json.Unmarshal([]byte(cpeJSON), &cpes)

	c.JSON(http.StatusOK, gin.H{
		"cve_id": cveID, "description": desc, "cvss_score": cvss, "cvss_vector": vector,
		"epss_score": epss, "epss_percentile": epssP, "kev_known_exploited": kev > 0,
		"cwe_ids": cweIDs, "category": cat, "affected_vendor": aVendor,
		"affected_product": aProduct, "affected_versions": aVersions,
		"cpe_entries": cpes, "ai_analysis": aiAnalysis, "references": refs,
		"published_at": pubAt, "modified_at": modAt, "fetched_at": fetchAt,
	})
}

// SaveAIAnalysis stores an AI-generated analysis for a CVE.
func (h *CVEFeedHandler) SaveAIAnalysis(c *gin.Context) {
	cveID := c.Param("cve_id")
	var req struct {
		Analysis string `json:"analysis"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Analysis == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "analysis text required"})
		return
	}
	_, err := h.db.Exec("UPDATE cve_cache SET ai_analysis = ? WHERE cve_id = ?", req.Analysis, cveID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetCategories returns all CVE categories with counts.
func (h *CVEFeedHandler) GetCategories(c *gin.Context) {
	rows, err := h.db.Query(`SELECT category, COUNT(*), ROUND(AVG(COALESCE(cvss_score, 0)), 1)
		FROM cve_cache GROUP BY category ORDER BY COUNT(*) DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var cat string
		var cnt int
		var avgCvss float64
		if rows.Scan(&cat, &cnt, &avgCvss) == nil {
			out = append(out, gin.H{"category": cat, "count": cnt, "avg_cvss": avgCvss})
		}
	}
	c.JSON(http.StatusOK, gin.H{"categories": out})
}

func (h *CVEFeedHandler) GetVulnCVELinks(c *gin.Context) {
	vulnID := c.Param("id")
	rows, err := h.db.Query(`SELECT vcl.cve_id, vcl.linked_by, vcl.created_at,
		COALESCE(cc.description,''), COALESCE(cc.cvss_score, 0), COALESCE(cc.epss_score, 0),
		cc.kev_known_exploited, COALESCE(cc.category, 'other')
		FROM vulnerability_cve_links vcl
		LEFT JOIN cve_cache cc ON cc.cve_id = vcl.cve_id
		WHERE vcl.vulnerability_id = ?`, vulnID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var cveID, linkedBy, created, desc, cat string
		var cvss, epss float64
		var kev int
		if err := rows.Scan(&cveID, &linkedBy, &created, &desc, &cvss, &epss, &kev, &cat); err != nil {
			continue
		}
		out = append(out, gin.H{
			"cve_id": cveID, "linked_by": linkedBy, "created_at": created,
			"description": desc, "cvss_score": cvss, "epss_score": epss,
			"kev_known_exploited": kev > 0, "category": cat,
		})
	}
	c.JSON(http.StatusOK, gin.H{"cve_links": out})
}

func (h *CVEFeedHandler) LinkVulnCVE(c *gin.Context) {
	vulnID := c.Param("id")
	var req struct {
		CVEID string `json:"cve_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.CVEID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cve_id required"})
		return
	}
	_, err := h.db.Exec(`INSERT OR IGNORE INTO vulnerability_cve_links (vulnerability_id, cve_id, linked_by, created_at)
		VALUES (?, ?, 'manual', ?)`, vulnID, req.CVEID, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *CVEFeedHandler) UnlinkVulnCVE(c *gin.Context) {
	vulnID := c.Param("id")
	cveID := c.Param("cve_id")
	_, err := h.db.Exec("DELETE FROM vulnerability_cve_links WHERE vulnerability_id = ? AND cve_id = ?", vulnID, cveID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// FetchAndCacheFromNVD pulls recent CVEs from the NVD 2.0 API with full enrichment.
func (h *CVEFeedHandler) FetchAndCacheFromNVD() {
	now := time.Now().UTC()
	pubStart := now.AddDate(0, 0, -30).Format("2006-01-02T15:04:05.000")
	pubEnd := now.Format("2006-01-02T15:04:05.000")
	url := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%s&pubEndDate=%s&resultsPerPage=50",
		pubStart, pubEnd,
	)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		h.logger.Warn("NVD API fetch failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		h.logger.Warn("NVD API non-200", zap.Int("status", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		h.logger.Warn("NVD API read failed", zap.Error(err))
		return
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		h.logger.Warn("NVD API parse failed", zap.Error(err))
		return
	}

	count := 0
	for _, vuln := range nvdResp.Vulnerabilities {
		cve := vuln.CVE
		if cve.ID == "" {
			continue
		}

		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		var cvss *float64
		var vector string
		for _, m := range cve.Metrics.CvssV31 {
			score := m.CvssData.BaseScore
			cvss = &score
			vector = m.CvssData.VectorString
			break
		}
		if cvss == nil {
			for _, m := range cve.Metrics.CvssV30 {
				score := m.CvssData.BaseScore
				cvss = &score
				vector = m.CvssData.VectorString
				break
			}
		}

		// Extract CWE IDs
		var cweIDs []string
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if d.Lang == "en" && d.Value != "NVD-CWE-noinfo" && d.Value != "NVD-CWE-Other" {
					cweIDs = append(cweIDs, d.Value)
				}
			}
		}
		cweStr := strings.Join(cweIDs, ",")

		// Extract CPE matches (affected products)
		var vendor, product, versions string
		var cpeEntries []map[string]string
		for _, conf := range cve.Configurations {
			for _, node := range conf.Nodes {
				for _, match := range node.CpeMatch {
					parts := strings.Split(match.Criteria, ":")
					if len(parts) >= 5 {
						v := parts[3]
						p := parts[4]
						ver := ""
						if len(parts) >= 6 && parts[5] != "*" {
							ver = parts[5]
						}
						if vendor == "" {
							vendor = v
						}
						if product == "" {
							product = p
						}
						entry := map[string]string{"vendor": v, "product": p}
						if ver != "" {
							entry["version"] = ver
						}
						if match.VersionStartIncluding != "" {
							entry["version_start"] = match.VersionStartIncluding
						}
						if match.VersionEndExcluding != "" {
							entry["version_end"] = match.VersionEndExcluding
							if versions == "" {
								versions = "< " + match.VersionEndExcluding
							}
						}
						cpeEntries = append(cpeEntries, entry)
					}
				}
			}
		}
		cpeJSON, _ := json.Marshal(cpeEntries)
		if cpeEntries == nil {
			cpeJSON = []byte("[]")
		}

		// Auto-categorize
		category := categorize(cweIDs, vendor, product, desc)

		pubAt := cve.Published
		modAt := cve.LastModified

		var refsJSON string
		if len(cve.References) > 0 {
			urls := make([]string, 0, len(cve.References))
			for _, r := range cve.References {
				urls = append(urls, r.URL)
			}
			b, _ := json.Marshal(urls)
			refsJSON = string(b)
		} else {
			refsJSON = "[]"
		}

		_, err := h.db.Exec(`INSERT INTO cve_cache
			(cve_id, description, cvss_score, cvss_vector, cwe_ids, category,
			 affected_vendor, affected_product, affected_versions, cpe_json,
			 published_at, modified_at, references_json, fetched_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(cve_id) DO UPDATE SET
				description = excluded.description,
				cvss_score = COALESCE(excluded.cvss_score, cve_cache.cvss_score),
				cvss_vector = CASE WHEN excluded.cvss_vector != '' THEN excluded.cvss_vector ELSE cve_cache.cvss_vector END,
				cwe_ids = CASE WHEN excluded.cwe_ids != '' THEN excluded.cwe_ids ELSE cve_cache.cwe_ids END,
				category = CASE WHEN excluded.category != 'other' THEN excluded.category ELSE cve_cache.category END,
				affected_vendor = CASE WHEN excluded.affected_vendor != '' THEN excluded.affected_vendor ELSE cve_cache.affected_vendor END,
				affected_product = CASE WHEN excluded.affected_product != '' THEN excluded.affected_product ELSE cve_cache.affected_product END,
				affected_versions = CASE WHEN excluded.affected_versions != '' THEN excluded.affected_versions ELSE cve_cache.affected_versions END,
				cpe_json = CASE WHEN excluded.cpe_json != '[]' THEN excluded.cpe_json ELSE cve_cache.cpe_json END,
				published_at = COALESCE(excluded.published_at, cve_cache.published_at),
				modified_at = COALESCE(excluded.modified_at, cve_cache.modified_at),
				references_json = excluded.references_json,
				fetched_at = excluded.fetched_at`,
			cve.ID, desc, cvss, vector, cweStr, category,
			vendor, product, versions, string(cpeJSON),
			pubAt, modAt, refsJSON, now)
		if err != nil {
			h.logger.Debug("cve upsert failed", zap.String("cve", cve.ID), zap.Error(err))
			continue
		}
		count++
	}
	h.logger.Info("NVD CVE feed cached", zap.Int("count", count), zap.Int("total_returned", len(nvdResp.Vulnerabilities)))
}

// StartBackgroundRefresh launches a goroutine that refreshes the CVE cache periodically.
func (h *CVEFeedHandler) StartBackgroundRefresh(interval time.Duration) {
	go func() {
		h.FetchAndCacheFromNVD()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			h.FetchAndCacheFromNVD()
		}
	}()
}

// categorize derives a technology category from CWE IDs, vendor/product, and description keywords.
func categorize(cweIDs []string, vendor, product, desc string) string {
	lower := strings.ToLower(desc + " " + vendor + " " + product)

	// CWE-based classification
	cweSet := map[string]bool{}
	for _, c := range cweIDs {
		cweSet[c] = true
	}
	if cweSet["CWE-79"] || cweSet["CWE-80"] {
		return "web-xss"
	}
	if cweSet["CWE-89"] || cweSet["CWE-564"] {
		return "database-injection"
	}
	if cweSet["CWE-78"] || cweSet["CWE-77"] || cweSet["CWE-94"] {
		return "code-execution"
	}
	if cweSet["CWE-287"] || cweSet["CWE-306"] || cweSet["CWE-862"] || cweSet["CWE-863"] {
		return "authentication"
	}
	if cweSet["CWE-22"] || cweSet["CWE-23"] || cweSet["CWE-36"] {
		return "path-traversal"
	}
	if cweSet["CWE-120"] || cweSet["CWE-119"] || cweSet["CWE-125"] || cweSet["CWE-787"] || cweSet["CWE-416"] || cweSet["CWE-476"] {
		return "memory-corruption"
	}
	if cweSet["CWE-200"] || cweSet["CWE-532"] || cweSet["CWE-209"] {
		return "info-disclosure"
	}
	if cweSet["CWE-352"] {
		return "web-csrf"
	}
	if cweSet["CWE-918"] {
		return "web-ssrf"
	}
	if cweSet["CWE-502"] {
		return "deserialization"
	}
	if cweSet["CWE-311"] || cweSet["CWE-327"] || cweSet["CWE-330"] {
		return "cryptography"
	}
	if cweSet["CWE-400"] || cweSet["CWE-770"] {
		return "denial-of-service"
	}
	if cweSet["CWE-269"] || cweSet["CWE-250"] {
		return "privilege-escalation"
	}

	// Product/keyword-based classification
	if strings.Contains(lower, "kernel") || strings.Contains(lower, "linux kernel") {
		return "os-kernel"
	}
	if strings.Contains(lower, "windows") || strings.Contains(lower, "microsoft") {
		return "os-windows"
	}
	if strings.Contains(lower, "android") || strings.Contains(lower, "ios") || strings.Contains(lower, "mobile") {
		return "mobile"
	}
	if strings.Contains(lower, "chrome") || strings.Contains(lower, "firefox") || strings.Contains(lower, "safari") || strings.Contains(lower, "browser") {
		return "browser"
	}
	if strings.Contains(lower, "apache") || strings.Contains(lower, "nginx") || strings.Contains(lower, "iis") || strings.Contains(lower, "web server") || strings.Contains(lower, "httpd") {
		return "web-server"
	}
	if strings.Contains(lower, "wordpress") || strings.Contains(lower, "drupal") || strings.Contains(lower, "joomla") || strings.Contains(lower, "cms") {
		return "web-cms"
	}
	if strings.Contains(lower, "mysql") || strings.Contains(lower, "postgres") || strings.Contains(lower, "oracle") || strings.Contains(lower, "mssql") || strings.Contains(lower, "database") || strings.Contains(lower, "sql server") || strings.Contains(lower, "mongodb") || strings.Contains(lower, "redis") {
		return "database"
	}
	if strings.Contains(lower, "docker") || strings.Contains(lower, "kubernetes") || strings.Contains(lower, "container") || strings.Contains(lower, "k8s") {
		return "container"
	}
	if strings.Contains(lower, "ssl") || strings.Contains(lower, "tls") || strings.Contains(lower, "openssl") || strings.Contains(lower, "certificate") || strings.Contains(lower, "encrypt") {
		return "cryptography"
	}
	if strings.Contains(lower, "firmware") || strings.Contains(lower, "iot") || strings.Contains(lower, "router") || strings.Contains(lower, "switch") || strings.Contains(lower, "modem") {
		return "network-device"
	}
	if strings.Contains(lower, "api") || strings.Contains(lower, "rest") || strings.Contains(lower, "graphql") || strings.Contains(lower, "endpoint") {
		return "web-api"
	}
	if strings.Contains(lower, "cloud") || strings.Contains(lower, "aws") || strings.Contains(lower, "azure") || strings.Contains(lower, "gcp") {
		return "cloud"
	}
	if strings.Contains(lower, "java") || strings.Contains(lower, "spring") {
		return "lang-java"
	}
	if strings.Contains(lower, "python") || strings.Contains(lower, "django") || strings.Contains(lower, "flask") {
		return "lang-python"
	}
	if strings.Contains(lower, "node") || strings.Contains(lower, "npm") || strings.Contains(lower, "javascript") {
		return "lang-javascript"
	}
	if strings.Contains(lower, "php") || strings.Contains(lower, "laravel") {
		return "lang-php"
	}
	if strings.Contains(lower, "golang") || strings.Contains(lower, " go ") {
		return "lang-go"
	}
	if strings.Contains(lower, "ruby") || strings.Contains(lower, "rails") {
		return "lang-ruby"
	}
	if strings.Contains(lower, "smtp") || strings.Contains(lower, "email") || strings.Contains(lower, "mail server") {
		return "email"
	}
	if strings.Contains(lower, "dns") || strings.Contains(lower, "dhcp") || strings.Contains(lower, "network") {
		return "network"
	}
	if strings.Contains(lower, "scada") || strings.Contains(lower, "plc") || strings.Contains(lower, "ics") || strings.Contains(lower, "industrial") {
		return "ics-scada"
	}

	return "other"
}

// NVD 2.0 response structures
type nvdResponse struct {
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}
type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}
type nvdCVE struct {
	ID             string             `json:"id"`
	Published      string             `json:"published"`
	LastModified   string             `json:"lastModified"`
	Descriptions   []nvdDescription   `json:"descriptions"`
	Metrics        nvdMetrics         `json:"metrics"`
	References     []nvdReference     `json:"references"`
	Weaknesses     []nvdWeakness      `json:"weaknesses"`
	Configurations []nvdConfiguration `json:"configurations"`
}
type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
type nvdMetrics struct {
	CvssV31 []nvdCvssEntry `json:"cvssMetricV31"`
	CvssV30 []nvdCvssEntry `json:"cvssMetricV30"`
}
type nvdCvssEntry struct {
	CvssData nvdCvssData `json:"cvssData"`
}
type nvdCvssData struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}
type nvdReference struct {
	URL string `json:"url"`
}
type nvdWeakness struct {
	Description []nvdDescription `json:"description"`
}
type nvdConfiguration struct {
	Nodes []nvdNode `json:"nodes"`
}
type nvdNode struct {
	CpeMatch []nvdCpeMatch `json:"cpeMatch"`
}
type nvdCpeMatch struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}
