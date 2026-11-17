package handler

import (
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type OWASPTestHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewOWASPTestHandler(db *database.DB, logger *zap.Logger) *OWASPTestHandler {
	return &OWASPTestHandler{db: db, logger: logger}
}

func (h *OWASPTestHandler) ListTestCases(c *gin.Context) {
	category := c.Query("category")
	query := "SELECT id, category, subcategory, test_id, title, description, severity_default FROM owasp_test_cases ORDER BY category, test_id"
	args := []interface{}{}
	if category != "" {
		query = "SELECT id, category, subcategory, test_id, title, description, severity_default FROM owasp_test_cases WHERE category = ? ORDER BY test_id"
		args = append(args, category)
	}
	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, cat, sub, tid, title, desc, sev string
		if err := rows.Scan(&id, &cat, &sub, &tid, &title, &desc, &sev); err != nil {
			continue
		}
		out = append(out, gin.H{"id": id, "category": cat, "subcategory": sub, "test_id": tid, "title": title, "description": desc, "severity_default": sev})
	}
	c.JSON(http.StatusOK, gin.H{"test_cases": out})
}

func (h *OWASPTestHandler) GetEngagementResults(c *gin.Context) {
	engID := c.Param("id")
	status := c.Query("status")
	query := `SELECT etr.id, etr.test_case_id, etr.status, etr.findings_summary, etr.vulnerability_id,
	                 etr.executed_by, etr.executed_at,
	                 COALESCE(otc.category,''), COALESCE(otc.test_id,''), COALESCE(otc.title,'')
	          FROM engagement_test_results etr
	          LEFT JOIN owasp_test_cases otc ON otc.id = etr.test_case_id
	          WHERE etr.engagement_id = ?`
	args := []interface{}{engID}
	if status != "" {
		query += " AND etr.status = ?"
		args = append(args, status)
	}
	query += " ORDER BY otc.category, otc.test_id"
	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, tcID, st, summary, vulnID, execBy, execAt, cat, tid, title string
		if err := rows.Scan(&id, &tcID, &st, &summary, &vulnID, &execBy, &execAt, &cat, &tid, &title); err != nil {
			continue
		}
		out = append(out, gin.H{
			"id": id, "test_case_id": tcID, "status": st, "findings_summary": summary,
			"vulnerability_id": vulnID, "executed_by": execBy, "executed_at": execAt,
			"category": cat, "test_id": tid, "title": title,
		})
	}
	c.JSON(http.StatusOK, gin.H{"results": out})
}

func (h *OWASPTestHandler) UpdateTestResult(c *gin.Context) {
	engID := c.Param("id")
	resultID := c.Param("result_id")
	var req struct {
		Status          string `json:"status"`
		FindingsSummary string `json:"findings_summary"`
		VulnerabilityID string `json:"vulnerability_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	_, err := h.db.Exec(`UPDATE engagement_test_results SET status = ?, findings_summary = ?, vulnerability_id = ?, executed_at = ?
		WHERE id = ? AND engagement_id = ?`, req.Status, req.FindingsSummary, req.VulnerabilityID, time.Now(), resultID, engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *OWASPTestHandler) InitEngagementTests(c *gin.Context) {
	engID := c.Param("id")
	rows, err := h.db.Query("SELECT id FROM owasp_test_cases ORDER BY category, test_id")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		var tcID string
		if err := rows.Scan(&tcID); err != nil {
			continue
		}
		id := uuid.NewString()
		_, _ = h.db.Exec(`INSERT OR IGNORE INTO engagement_test_results (id, engagement_id, test_case_id, status, created_at)
			VALUES (?, ?, ?, 'pending', ?)`, id, engID, tcID, time.Now())
		count++
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "initialized": count})
}

func (h *OWASPTestHandler) SeedTestCases() {
	var count int
	_ = h.db.QueryRow("SELECT COUNT(*) FROM owasp_test_cases").Scan(&count)
	if count > 0 {
		return
	}
	type tc struct{ cat, sub, tid, title string }
	cases := []tc{
		{"Information Gathering", "Fingerprint Web Server", "WSTG-INFO-02", "Fingerprint Web Server"},
		{"Information Gathering", "Review Webserver Metafiles", "WSTG-INFO-03", "Review Webserver Metafiles for Information Leakage"},
		{"Information Gathering", "Enumerate Applications", "WSTG-INFO-04", "Enumerate Applications on Webserver"},
		{"Information Gathering", "Review Webpage Content", "WSTG-INFO-05", "Review Webpage Content for Information Leakage"},
		{"Information Gathering", "Identify Application Entry Points", "WSTG-INFO-06", "Identify Application Entry Points"},
		{"Information Gathering", "Map Execution Paths", "WSTG-INFO-07", "Map Execution Paths Through Application"},
		{"Information Gathering", "Fingerprint Web Application Framework", "WSTG-INFO-08", "Fingerprint Web Application Framework"},
		{"Information Gathering", "Fingerprint Web Application", "WSTG-INFO-09", "Fingerprint Web Application"},
		{"Configuration and Deployment", "Test Network Infrastructure", "WSTG-CONF-01", "Test Network Infrastructure Configuration"},
		{"Configuration and Deployment", "Test Application Platform", "WSTG-CONF-02", "Test Application Platform Configuration"},
		{"Configuration and Deployment", "Test File Extensions Handling", "WSTG-CONF-03", "Test File Extensions Handling for Sensitive Information"},
		{"Configuration and Deployment", "Review Old Backup Files", "WSTG-CONF-04", "Review Old Backup and Unreferenced Files"},
		{"Configuration and Deployment", "Enumerate Infrastructure Interfaces", "WSTG-CONF-05", "Enumerate Infrastructure and Application Admin Interfaces"},
		{"Configuration and Deployment", "Test HTTP Methods", "WSTG-CONF-06", "Test HTTP Methods"},
		{"Configuration and Deployment", "Test HTTP Strict Transport Security", "WSTG-CONF-07", "Test HTTP Strict Transport Security"},
		{"Configuration and Deployment", "Test Cross Domain Policy", "WSTG-CONF-08", "Test RIA Cross Domain Policy"},
		{"Identity Management", "Test Role Definitions", "WSTG-IDNT-01", "Test Role Definitions"},
		{"Identity Management", "Test User Registration", "WSTG-IDNT-02", "Test User Registration Process"},
		{"Identity Management", "Test Account Provisioning", "WSTG-IDNT-03", "Test Account Provisioning Process"},
		{"Identity Management", "Test Account Enumeration", "WSTG-IDNT-04", "Testing for Account Enumeration and Guessable User Account"},
		{"Authentication", "Test Credentials Transport", "WSTG-ATHN-01", "Testing for Credentials Transported over an Encrypted Channel"},
		{"Authentication", "Test Default Credentials", "WSTG-ATHN-02", "Testing for Default Credentials"},
		{"Authentication", "Test Weak Lock Out", "WSTG-ATHN-03", "Testing for Weak Lock Out Mechanism"},
		{"Authentication", "Test Bypassing Auth Schema", "WSTG-ATHN-04", "Testing for Bypassing Authentication Schema"},
		{"Authentication", "Test Remember Password", "WSTG-ATHN-05", "Testing for Vulnerable Remember Password"},
		{"Authentication", "Test Browser Cache Weakness", "WSTG-ATHN-06", "Testing for Browser Cache Weaknesses"},
		{"Authentication", "Test Weak Password Policy", "WSTG-ATHN-07", "Testing for Weak Password Policy"},
		{"Authentication", "Test Weak Security Question", "WSTG-ATHN-08", "Testing for Weak Security Question/Answer"},
		{"Authentication", "Test Weak Password Change", "WSTG-ATHN-09", "Testing for Weak Password Change or Reset Functionalities"},
		{"Authorization", "Test Directory Traversal", "WSTG-ATHZ-01", "Testing Directory Traversal File Include"},
		{"Authorization", "Test Bypassing Auth Schema", "WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema"},
		{"Authorization", "Test Privilege Escalation", "WSTG-ATHZ-03", "Testing for Privilege Escalation"},
		{"Authorization", "Test IDOR", "WSTG-ATHZ-04", "Testing for Insecure Direct Object References"},
		{"Session Management", "Test Session Management Schema", "WSTG-SESS-01", "Testing for Session Management Schema"},
		{"Session Management", "Test Cookies Attributes", "WSTG-SESS-02", "Testing for Cookies Attributes"},
		{"Session Management", "Test Session Fixation", "WSTG-SESS-03", "Testing for Session Fixation"},
		{"Session Management", "Test Exposed Session Variables", "WSTG-SESS-04", "Testing for Exposed Session Variables"},
		{"Session Management", "Test CSRF", "WSTG-SESS-05", "Testing for Cross Site Request Forgery"},
		{"Session Management", "Test Logout Functionality", "WSTG-SESS-06", "Testing for Logout Functionality"},
		{"Session Management", "Test Session Timeout", "WSTG-SESS-07", "Testing Session Timeout"},
		{"Input Validation", "Test Reflected XSS", "WSTG-INPV-01", "Testing for Reflected Cross Site Scripting"},
		{"Input Validation", "Test Stored XSS", "WSTG-INPV-02", "Testing for Stored Cross Site Scripting"},
		{"Input Validation", "Test HTTP Verb Tampering", "WSTG-INPV-03", "Testing for HTTP Verb Tampering"},
		{"Input Validation", "Test HTTP Parameter Pollution", "WSTG-INPV-04", "Testing for HTTP Parameter Pollution"},
		{"Input Validation", "Test SQL Injection", "WSTG-INPV-05", "Testing for SQL Injection"},
		{"Input Validation", "Test LDAP Injection", "WSTG-INPV-06", "Testing for LDAP Injection"},
		{"Input Validation", "Test XML Injection", "WSTG-INPV-07", "Testing for XML Injection"},
		{"Input Validation", "Test SSI Injection", "WSTG-INPV-08", "Testing for SSI Injection"},
		{"Input Validation", "Test XPath Injection", "WSTG-INPV-09", "Testing for XPath Injection"},
		{"Input Validation", "Test IMAP/SMTP Injection", "WSTG-INPV-10", "Testing for IMAP SMTP Injection"},
		{"Input Validation", "Test Code Injection", "WSTG-INPV-11", "Testing for Code Injection"},
		{"Input Validation", "Test Command Injection", "WSTG-INPV-12", "Testing for Command Injection"},
		{"Input Validation", "Test Format String Injection", "WSTG-INPV-13", "Testing for Format String Injection"},
		{"Input Validation", "Test Host Header Injection", "WSTG-INPV-14", "Testing for Host Header Injection"},
		{"Input Validation", "Test Server-Side Template Injection", "WSTG-INPV-15", "Testing for Server-Side Template Injection"},
		{"Input Validation", "Test Server-Side Request Forgery", "WSTG-INPV-16", "Testing for Server-Side Request Forgery"},
		{"Error Handling", "Test Improper Error Handling", "WSTG-ERRH-01", "Testing for Improper Error Handling"},
		{"Error Handling", "Test Stack Traces", "WSTG-ERRH-02", "Testing for Stack Traces"},
		{"Cryptography", "Test Weak Transport Layer Security", "WSTG-CRYP-01", "Testing for Weak Transport Layer Security"},
		{"Cryptography", "Test Padding Oracle", "WSTG-CRYP-02", "Testing for Padding Oracle"},
		{"Cryptography", "Test Sensitive Info Sent Unencrypted", "WSTG-CRYP-03", "Testing for Sensitive Information Sent via Unencrypted Channels"},
		{"Cryptography", "Test Weak Encryption", "WSTG-CRYP-04", "Testing for Weak Encryption"},
		{"Business Logic", "Test Business Logic Data Validation", "WSTG-BUSL-01", "Test Business Logic Data Validation"},
		{"Business Logic", "Test Ability to Forge Requests", "WSTG-BUSL-02", "Test Ability to Forge Requests"},
		{"Business Logic", "Test Integrity Checks", "WSTG-BUSL-03", "Test Integrity Checks"},
		{"Business Logic", "Test Process Timing", "WSTG-BUSL-04", "Test for Process Timing"},
		{"Business Logic", "Test Function Use Limits", "WSTG-BUSL-05", "Test Number of Times a Function Can Be Used Limits"},
		{"Business Logic", "Test Circumvention of Workflows", "WSTG-BUSL-06", "Testing for the Circumvention of Work Flows"},
		{"Business Logic", "Test Defenses Against App Misuse", "WSTG-BUSL-07", "Test Defenses Against Application Misuse"},
		{"Business Logic", "Test Upload Unexpected File Types", "WSTG-BUSL-08", "Test Upload of Unexpected File Types"},
		{"Business Logic", "Test Upload Malicious Files", "WSTG-BUSL-09", "Test Upload of Malicious Files"},
		{"Client-Side", "Test DOM-Based XSS", "WSTG-CLNT-01", "Testing for DOM-Based Cross Site Scripting"},
		{"Client-Side", "Test JavaScript Execution", "WSTG-CLNT-02", "Testing for JavaScript Execution"},
		{"Client-Side", "Test HTML Injection", "WSTG-CLNT-03", "Testing for HTML Injection"},
		{"Client-Side", "Test Client-Side URL Redirect", "WSTG-CLNT-04", "Testing for Client-side URL Redirect"},
		{"Client-Side", "Test CSS Injection", "WSTG-CLNT-05", "Testing for CSS Injection"},
		{"Client-Side", "Test Client-Side Resource Manipulation", "WSTG-CLNT-06", "Testing for Client-side Resource Manipulation"},
		{"Client-Side", "Test Cross Origin Resource Sharing", "WSTG-CLNT-07", "Testing Cross Origin Resource Sharing"},
		{"Client-Side", "Test Clickjacking", "WSTG-CLNT-09", "Testing for Clickjacking"},
		{"Client-Side", "Test WebSockets", "WSTG-CLNT-10", "Testing WebSockets"},
		{"Client-Side", "Test Web Messaging", "WSTG-CLNT-11", "Testing Web Messaging"},
		{"Client-Side", "Test Browser Storage", "WSTG-CLNT-12", "Testing Browser Storage"},
		{"API Testing", "Test GraphQL", "WSTG-APIT-01", "Testing GraphQL"},
	}
	for _, tc := range cases {
		id := uuid.NewString()
		_, _ = h.db.Exec(`INSERT OR IGNORE INTO owasp_test_cases (id, category, subcategory, test_id, title) VALUES (?, ?, ?, ?, ?)`,
			id, tc.cat, tc.sub, tc.tid, tc.title)
	}
	h.logger.Info("seeded OWASP test cases", zap.Int("count", len(cases)))
}
