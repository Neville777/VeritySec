package handler

import (
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type MitreAttackHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewMitreAttackHandler(db *database.DB, logger *zap.Logger) *MitreAttackHandler {
	return &MitreAttackHandler{db: db, logger: logger}
}

type mitreMapping struct {
	TechniqueID string `json:"technique_id"`
	Confidence  string `json:"confidence"`
	MappedBy    string `json:"mapped_by"`
	CreatedAt   string `json:"created_at"`
	Tactic      string `json:"tactic,omitempty"`
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"`
}

func (h *MitreAttackHandler) ListTechniques(c *gin.Context) {
	tactic := c.Query("tactic")
	query := "SELECT id, tactic, name, description, url FROM mitre_attack_techniques ORDER BY tactic, id"
	args := []interface{}{}
	if tactic != "" {
		query = "SELECT id, tactic, name, description, url FROM mitre_attack_techniques WHERE tactic = ? ORDER BY id"
		args = append(args, tactic)
	}
	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, tac, name, desc, url string
		if err := rows.Scan(&id, &tac, &name, &desc, &url); err != nil {
			continue
		}
		out = append(out, gin.H{"id": id, "tactic": tac, "name": name, "description": desc, "url": url})
	}
	c.JSON(http.StatusOK, gin.H{"techniques": out})
}

func (h *MitreAttackHandler) GetVulnMappings(c *gin.Context) {
	vulnID := c.Param("id")
	rows, err := h.db.Query(`
		SELECT vam.technique_id, vam.confidence, vam.mapped_by, vam.created_at,
		       COALESCE(mat.tactic,''), COALESCE(mat.name,''), COALESCE(mat.url,'')
		FROM vulnerability_attack_mappings vam
		LEFT JOIN mitre_attack_techniques mat ON mat.id = vam.technique_id
		WHERE vam.vulnerability_id = ?
		ORDER BY mat.tactic, vam.technique_id`, vulnID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []mitreMapping
	for rows.Next() {
		var m mitreMapping
		if err := rows.Scan(&m.TechniqueID, &m.Confidence, &m.MappedBy, &m.CreatedAt, &m.Tactic, &m.Name, &m.URL); err != nil {
			continue
		}
		out = append(out, m)
	}
	c.JSON(http.StatusOK, gin.H{"mappings": out})
}

func (h *MitreAttackHandler) AddVulnMapping(c *gin.Context) {
	vulnID := c.Param("id")
	var req struct {
		TechniqueID string `json:"technique_id"`
		Confidence  string `json:"confidence"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.TechniqueID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "technique_id required"})
		return
	}
	conf := req.Confidence
	if conf != "low" && conf != "high" {
		conf = "medium"
	}
	_, err := h.db.Exec(`INSERT OR REPLACE INTO vulnerability_attack_mappings (vulnerability_id, technique_id, confidence, mapped_by, created_at)
		VALUES (?, ?, ?, 'manual', ?)`, vulnID, req.TechniqueID, conf, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *MitreAttackHandler) RemoveVulnMapping(c *gin.Context) {
	vulnID := c.Param("id")
	techID := c.Param("technique_id")
	_, err := h.db.Exec("DELETE FROM vulnerability_attack_mappings WHERE vulnerability_id = ? AND technique_id = ?", vulnID, techID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *MitreAttackHandler) SeedTechniques() {
	var count int
	_ = h.db.QueryRow("SELECT COUNT(*) FROM mitre_attack_techniques").Scan(&count)
	if count > 0 {
		return
	}
	type t struct{ id, tactic, name string }
	techniques := []t{
		{"T1595", "Reconnaissance", "Active Scanning"},
		{"T1592", "Reconnaissance", "Gather Victim Host Information"},
		{"T1589", "Reconnaissance", "Gather Victim Identity Information"},
		{"T1590", "Reconnaissance", "Gather Victim Network Information"},
		{"T1598", "Reconnaissance", "Phishing for Information"},
		{"T1596", "Reconnaissance", "Search Open Technical Databases"},
		{"T1593", "Reconnaissance", "Search Open Websites/Domains"},
		{"T1190", "Initial Access", "Exploit Public-Facing Application"},
		{"T1133", "Initial Access", "External Remote Services"},
		{"T1566", "Initial Access", "Phishing"},
		{"T1195", "Initial Access", "Supply Chain Compromise"},
		{"T1199", "Initial Access", "Trusted Relationship"},
		{"T1078", "Initial Access", "Valid Accounts"},
		{"T1059", "Execution", "Command and Scripting Interpreter"},
		{"T1203", "Execution", "Exploitation for Client Execution"},
		{"T1053", "Execution", "Scheduled Task/Job"},
		{"T1204", "Execution", "User Execution"},
		{"T1098", "Persistence", "Account Manipulation"},
		{"T1547", "Persistence", "Boot or Logon Autostart Execution"},
		{"T1136", "Persistence", "Create Account"},
		{"T1543", "Persistence", "Create or Modify System Process"},
		{"T1546", "Persistence", "Event Triggered Execution"},
		{"T1574", "Persistence", "Hijack Execution Flow"},
		{"T1505", "Persistence", "Server Software Component"},
		{"T1548", "Privilege Escalation", "Abuse Elevation Control Mechanism"},
		{"T1134", "Privilege Escalation", "Access Token Manipulation"},
		{"T1068", "Privilege Escalation", "Exploitation for Privilege Escalation"},
		{"T1055", "Privilege Escalation", "Process Injection"},
		{"T1557", "Credential Access", "Adversary-in-the-Middle"},
		{"T1110", "Credential Access", "Brute Force"},
		{"T1555", "Credential Access", "Credentials from Password Stores"},
		{"T1003", "Credential Access", "OS Credential Dumping"},
		{"T1552", "Credential Access", "Unsecured Credentials"},
		{"T1046", "Discovery", "Network Service Discovery"},
		{"T1135", "Discovery", "Network Share Discovery"},
		{"T1082", "Discovery", "System Information Discovery"},
		{"T1016", "Discovery", "System Network Configuration Discovery"},
		{"T1021", "Lateral Movement", "Remote Services"},
		{"T1210", "Lateral Movement", "Exploitation of Remote Services"},
		{"T1570", "Lateral Movement", "Lateral Tool Transfer"},
		{"T1005", "Collection", "Data from Local System"},
		{"T1114", "Collection", "Email Collection"},
		{"T1056", "Collection", "Input Capture"},
		{"T1071", "Command and Control", "Application Layer Protocol"},
		{"T1573", "Command and Control", "Encrypted Channel"},
		{"T1105", "Command and Control", "Ingress Tool Transfer"},
		{"T1572", "Command and Control", "Protocol Tunneling"},
		{"T1090", "Command and Control", "Proxy"},
		{"T1041", "Exfiltration", "Exfiltration Over C2 Channel"},
		{"T1567", "Exfiltration", "Exfiltration Over Web Service"},
		{"T1486", "Impact", "Data Encrypted for Impact"},
		{"T1565", "Impact", "Data Manipulation"},
		{"T1499", "Impact", "Endpoint Denial of Service"},
		{"T1498", "Impact", "Network Denial of Service"},
	}
	for _, tech := range techniques {
		_, _ = h.db.Exec("INSERT OR IGNORE INTO mitre_attack_techniques (id, tactic, name) VALUES (?, ?, ?)", tech.id, tech.tactic, tech.name)
	}
	h.logger.Info("seeded MITRE ATT&CK techniques", zap.Int("count", len(techniques)))
}
