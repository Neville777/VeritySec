package handler

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"veritysec/internal/audit"
	"veritysec/internal/config"
	"veritysec/internal/database"
	"veritysec/internal/skillpackage"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// SkillsHandler: Skills handler (on disk + Eino spec; loaded at runtime by the Eino ADK skill middleware)
type SkillsHandler struct {
	config     *config.Config
	configPath string
	logger     *zap.Logger
	db         *database.DB // Database connection (legacy statistics; MCP list/read has been removed)
	audit      *audit.Service
}

// SetAudit wires platform audit logging.
// skillTagAliases maps Chinese search terms to the English skill tags they were translated to.
var skillTagAliases = map[string]string{
	"penetration-testing": "penetration-testing",
	"red-team": "red-team",
}

func (h *SkillsHandler) SetAudit(s *audit.Service) {
	h.audit = s
}

// NewSkillsHandler creates a new Skills handler
func NewSkillsHandler(cfg *config.Config, configPath string, logger *zap.Logger) *SkillsHandler {
	return &SkillsHandler{
		config:     cfg,
		configPath: configPath,
		logger:     logger,
	}
}

func (h *SkillsHandler) skillsRootAbs() string {
	skillsDir := h.config.SkillsDir
	if skillsDir == "" {
		skillsDir = "skills"
	}
	configDir := filepath.Dir(h.configPath)
	if !filepath.IsAbs(skillsDir) {
		skillsDir = filepath.Join(configDir, skillsDir)
	}
	return skillsDir
}

// SetDB sets the database connection (used to get call statistics)
func (h *SkillsHandler) SetDB(db *database.DB) {
	h.db = db
}

// GetSkills gets the list of all skills (supports pagination and search)
func (h *SkillsHandler) GetSkills(c *gin.Context) {
	allSummaries, err := skillpackage.ListSkillSummaries(h.skillsRootAbs())
	if err != nil {
		h.logger.Error("Failed to get the skills list", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	searchKeyword := strings.TrimSpace(c.Query("search"))

	allSkillsInfo := make([]map[string]interface{}, 0, len(allSummaries))
	for _, s := range allSummaries {
		skillInfo := map[string]interface{}{
			"id":           s.ID,
			"name":         s.Name,
			"dir_name":     s.DirName,
			"description":  s.Description,
			"version":      s.Version,
			"path":         s.Path,
			"tags":         s.Tags,
			"triggers":     s.Triggers,
			"script_count": s.ScriptCount,
			"file_count":   s.FileCount,
			"progressive":  s.Progressive,
			"file_size":    s.FileSize,
			"mod_time":     s.ModTime,
		}
		allSkillsInfo = append(allSkillsInfo, skillInfo)
	}

	filteredSkillsInfo := allSkillsInfo
	if searchKeyword != "" {
		keywordLower := strings.ToLower(searchKeyword)
		// Skill tags were translated to English; keep Chinese searches working by mapping them to the English tag.
		tagAlias := skillTagAliases[strings.TrimSpace(searchKeyword)]
		filteredSkillsInfo = make([]map[string]interface{}, 0)
		for _, skillInfo := range allSkillsInfo {
			id := strings.ToLower(fmt.Sprintf("%v", skillInfo["id"]))
			name := strings.ToLower(fmt.Sprintf("%v", skillInfo["name"]))
			description := strings.ToLower(fmt.Sprintf("%v", skillInfo["description"]))
			path := strings.ToLower(fmt.Sprintf("%v", skillInfo["path"]))
			version := strings.ToLower(fmt.Sprintf("%v", skillInfo["version"]))
			tagsJoined := ""
			if tags, ok := skillInfo["tags"].([]string); ok {
				tagsJoined = strings.ToLower(strings.Join(tags, " "))
			}
			trigJoined := ""
			if tr, ok := skillInfo["triggers"].([]string); ok {
				trigJoined = strings.ToLower(strings.Join(tr, " "))
			}
			if strings.Contains(id, keywordLower) ||
				strings.Contains(name, keywordLower) ||
				strings.Contains(description, keywordLower) ||
				strings.Contains(path, keywordLower) ||
				strings.Contains(version, keywordLower) ||
				strings.Contains(tagsJoined, keywordLower) ||
				(tagAlias != "" && strings.Contains(tagsJoined, tagAlias)) ||
				strings.Contains(trigJoined, keywordLower) {
				filteredSkillsInfo = append(filteredSkillsInfo, skillInfo)
			}
		}
	}

	// Pagination parameters
	limit := 20 // Default 20 items per page
	offset := 0
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := parseInt(limitStr); err == nil && parsed > 0 {
			// Allow a larger limit for search scenarios, but cap it at a reasonable maximum (10000)
			if parsed <= 10000 {
				limit = parsed
			} else {
				limit = 10000
			}
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsed, err := parseInt(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Compute the pagination range
	total := len(filteredSkillsInfo)
	start := offset
	end := offset + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	// Get the skill list for the current page
	var paginatedSkillsInfo []map[string]interface{}
	if start < end {
		paginatedSkillsInfo = filteredSkillsInfo[start:end]
	} else {
		paginatedSkillsInfo = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"skills": paginatedSkillsInfo,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetSkill gets the detailed information of a single skill
func (h *SkillsHandler) GetSkill(c *gin.Context) {
	skillName := c.Param("name")
	if skillName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Skill name cannot be empty"})
		return
	}

	resPath := strings.TrimSpace(c.Query("resource_path"))
	if resPath == "" {
		resPath = strings.TrimSpace(c.Query("skill_script_path"))
	}
	if resPath != "" {
		content, err := skillpackage.ReadScriptText(h.skillsRootAbs(), skillName, resPath, 0)
		if err != nil {
			h.logger.Warn("Failed to read skill resources", zap.String("skill", skillName), zap.String("path", resPath), zap.Error(err))
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"skill": map[string]interface{}{
				"id": skillName,
			},
			"resource": map[string]interface{}{
				"path":    resPath,
				"content": content,
			},
		})
		return
	}

	depthStr := strings.ToLower(strings.TrimSpace(c.DefaultQuery("depth", "full")))
	section := strings.TrimSpace(c.Query("section"))
	opt := skillpackage.LoadOptions{Section: section}
	switch depthStr {
	case "summary":
		opt.Depth = "summary"
	case "full", "":
		opt.Depth = "full"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "depth only supports summary or full"})
		return
	}

	skill, err := skillpackage.LoadSkill(h.skillsRootAbs(), skillName, opt)
	if err != nil {
		h.logger.Warn("Failed to load the skill", zap.String("skill", skillName), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Skill not found: " + err.Error()})
		return
	}

	skillPath := skill.Path
	skillFile := filepath.Join(skillPath, "SKILL.md")

	fileInfo, _ := os.Stat(skillFile)
	var fileSize int64
	var modTime string
	if fileInfo != nil {
		fileSize = fileInfo.Size()
		modTime = fileInfo.ModTime().Format("2006-01-02 15:04:05")
	}

	c.JSON(http.StatusOK, gin.H{
		"skill": map[string]interface{}{
			"id":            skill.DirName,
			"name":          skill.Name,
			"description":   skill.Description,
			"content":       skill.Content,
			"path":          skill.Path,
			"version":       skill.Version,
			"tags":          skill.Tags,
			"scripts":       skill.Scripts,
			"sections":      skill.Sections,
			"package_files": skill.PackageFiles,
			"file_size":     fileSize,
			"mod_time":      modTime,
			"depth":         depthStr,
			"section":       section,
		},
	})
}

// ListSkillPackageFiles lists all files in a skill directory (Agent Skills layout).
func (h *SkillsHandler) ListSkillPackageFiles(c *gin.Context) {
	skillID := c.Param("name")
	files, err := skillpackage.ListPackageFiles(h.skillsRootAbs(), skillID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"files": files})
}

// GetSkillPackageFile returns one file by relative path (?path=).
func (h *SkillsHandler) GetSkillPackageFile(c *gin.Context) {
	skillID := c.Param("name")
	rel := strings.TrimSpace(c.Query("path"))
	if rel == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query path is required"})
		return
	}
	b, err := skillpackage.ReadPackageFile(h.skillsRootAbs(), skillID, rel, 0)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"path": rel, "content": string(b)})
}

// PutSkillPackageFile writes a file inside the skill package.
func (h *SkillsHandler) PutSkillPackageFile(c *gin.Context) {
	skillID := c.Param("name")
	var req struct {
		Path    string `json:"path" binding:"required"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters: " + err.Error()})
		return
	}
	if req.Path == "SKILL.md" {
		if err := skillpackage.ValidateSkillMDPackage([]byte(req.Content), skillID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	if err := skillpackage.WritePackageFile(h.skillsRootAbs(), skillID, req.Path, []byte(req.Content)); err != nil {
		h.logger.Error("Failed to write the skill file", zap.String("skill", skillID), zap.String("path", req.Path), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "saved", "path": req.Path})
}

// GetSkillBoundRoles gets the list of roles bound to the specified skill
func (h *SkillsHandler) GetSkillBoundRoles(c *gin.Context) {
	skillName := c.Param("name")
	if skillName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Skill name cannot be empty"})
		return
	}

	boundRoles := h.getRolesBoundToSkill(skillName)
	c.JSON(http.StatusOK, gin.H{
		"skill":       skillName,
		"bound_roles": boundRoles,
		"bound_count": len(boundRoles),
	})
}

// getRolesBoundToSkill (reserved): roles no longer configure skill bindings, so this always returns an empty list.
func (h *SkillsHandler) getRolesBoundToSkill(skillName string) []string {
	_ = skillName
	return nil
}

// CreateSkill creates a new skill (standard Agent Skills: generates SKILL.md with YAML front matter)
func (h *SkillsHandler) CreateSkill(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description" binding:"required"`
		Content     string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters: " + err.Error()})
		return
	}

	if !isValidSkillName(req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The skill directory name must be lowercase letters, digits or hyphens (consistent with the Agent Skills name)"})
		return
	}

	manifest := &skillpackage.SkillManifest{
		Name:        req.Name,
		Description: strings.TrimSpace(req.Description),
	}
	skillMD, err := skillpackage.BuildSkillMD(manifest, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := skillpackage.ValidateSkillMDPackage(skillMD, req.Name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	skillDir := filepath.Join(h.skillsRootAbs(), req.Name)
	if err := os.MkdirAll(skillDir, 0755); err != nil {
		h.logger.Error("Failed to create the skill directory", zap.String("skill", req.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create the skill directory: " + err.Error()})
		return
	}

	if _, err := os.Stat(filepath.Join(skillDir, "SKILL.md")); err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Skill already exists"})
		return
	}

	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), skillMD, 0644); err != nil {
		h.logger.Error("Failed to create SKILL.md", zap.String("skill", req.Name), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create SKILL.md: " + err.Error()})
		return
	}

	h.logger.Info("Skill created successfully", zap.String("skill", req.Name))
	if h.audit != nil {
		h.audit.RecordOK(c, "skill", "create", "Create Skill", "skill", req.Name, nil)
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Skill created",
		"skill": map[string]interface{}{
			"name": req.Name,
			"path": skillDir,
		},
	})
}

// UpdateSkill updates SKILL.md (keeps front matter fields other than description; optionally overrides description)
func (h *SkillsHandler) UpdateSkill(c *gin.Context) {
	skillName := c.Param("name")
	if skillName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Skill name cannot be empty"})
		return
	}

	var req struct {
		Description string `json:"description"`
		Content     string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request parameters: " + err.Error()})
		return
	}

	mdPath := filepath.Join(h.skillsRootAbs(), skillName, "SKILL.md")
	raw, err := os.ReadFile(mdPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Skill not found: " + err.Error()})
		return
	}
	m, _, err := skillpackage.ParseSkillMD(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Description != "" {
		m.Description = strings.TrimSpace(req.Description)
	}
	skillMD, err := skillpackage.BuildSkillMD(m, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := skillpackage.ValidateSkillMDPackage(skillMD, skillName); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	skillDir := filepath.Join(h.skillsRootAbs(), skillName)

	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), skillMD, 0644); err != nil {
		h.logger.Error("Failed to update SKILL.md", zap.String("skill", skillName), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update SKILL.md: " + err.Error()})
		return
	}

	h.logger.Info("Skill updated successfully", zap.String("skill", skillName))
	if h.audit != nil {
		h.audit.RecordOK(c, "skill", "update", "Update Skill", "skill", skillName, nil)
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Skill updated",
	})
}

// DeleteSkill deletes a skill
func (h *SkillsHandler) DeleteSkill(c *gin.Context) {
	skillName := c.Param("name")
	if skillName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Skill name cannot be empty"})
		return
	}

	// Check whether any role is bound to this skill; if so, remove the bindings automatically
	affectedRoles := h.removeSkillFromRoles(skillName)
	if len(affectedRoles) > 0 {
		h.logger.Info("Remove the skill binding from roles",
			zap.String("skill", skillName),
			zap.Strings("roles", affectedRoles))
	}

	skillDir := filepath.Join(h.skillsRootAbs(), skillName)
	if err := os.RemoveAll(skillDir); err != nil {
		h.logger.Error("Failed to delete the skill", zap.String("skill", skillName), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete the skill: " + err.Error()})
		return
	}
	responseMsg := "Skill deleted"
	if len(affectedRoles) > 0 {
		responseMsg = fmt.Sprintf("Skill deleted; binding automatically removed from %d roles: %s",
			len(affectedRoles), strings.Join(affectedRoles, ", "))
	}

	h.logger.Info("Skill deleted successfully", zap.String("skill", skillName))
	if h.audit != nil {
		h.audit.RecordOK(c, "skill", "delete", "Delete Skill", "skill", skillName, map[string]interface{}{
			"affected_roles": affectedRoles,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"message":        responseMsg,
		"affected_roles": affectedRoles,
	})
}

// GetSkillStats gets the skills call statistics
func (h *SkillsHandler) GetSkillStats(c *gin.Context) {
	skillList, err := skillpackage.ListSkillDirNames(h.skillsRootAbs())
	if err != nil {
		h.logger.Error("Failed to get the skills list", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	skillsDir := h.skillsRootAbs()

	// Load call statistics from the database
	var skillStatsMap map[string]*database.SkillStats
	if h.db != nil {
		dbStats, err := h.db.LoadSkillStats()
		if err != nil {
			h.logger.Warn("Failed to load Skills statistics from the database", zap.Error(err))
			skillStatsMap = make(map[string]*database.SkillStats)
		} else {
			skillStatsMap = dbStats
		}
	} else {
		skillStatsMap = make(map[string]*database.SkillStats)
	}

	// Build statistics (includes all skills, even those without call records)
	statsList := make([]map[string]interface{}, 0, len(skillList))
	totalCalls := 0
	totalSuccess := 0
	totalFailed := 0

	for _, skillName := range skillList {
		stat, exists := skillStatsMap[skillName]
		if !exists {
			stat = &database.SkillStats{
				SkillName:    skillName,
				TotalCalls:   0,
				SuccessCalls: 0,
				FailedCalls:  0,
			}
		}

		totalCalls += stat.TotalCalls
		totalSuccess += stat.SuccessCalls
		totalFailed += stat.FailedCalls

		lastCallTimeStr := ""
		if stat.LastCallTime != nil {
			lastCallTimeStr = stat.LastCallTime.Format("2006-01-02 15:04:05")
		}

		statsList = append(statsList, map[string]interface{}{
			"skill_name":     stat.SkillName,
			"total_calls":    stat.TotalCalls,
			"success_calls":  stat.SuccessCalls,
			"failed_calls":   stat.FailedCalls,
			"last_call_time": lastCallTimeStr,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"total_skills":  len(skillList),
		"total_calls":   totalCalls,
		"total_success": totalSuccess,
		"total_failed":  totalFailed,
		"skills_dir":    skillsDir,
		"stats":         statsList,
	})
}

// ClearSkillStats clears all Skills statistics
func (h *SkillsHandler) ClearSkillStats(c *gin.Context) {
	if h.db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection is not configured"})
		return
	}

	if err := h.db.ClearSkillStats(); err != nil {
		h.logger.Error("Failed to clear Skills statistics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear statistics: " + err.Error()})
		return
	}

	h.logger.Info("Cleared all Skills statistics")
	c.JSON(http.StatusOK, gin.H{
		"message": "Cleared all Skills statistics",
	})
}

// ClearSkillStatsByName clears the statistics of the specified skill
func (h *SkillsHandler) ClearSkillStatsByName(c *gin.Context) {
	skillName := c.Param("name")
	if skillName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Skill name cannot be empty"})
		return
	}

	if h.db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection is not configured"})
		return
	}

	if err := h.db.ClearSkillStatsByName(skillName); err != nil {
		h.logger.Error("Failed to clear the statistics of the specified skill", zap.String("skill", skillName), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear statistics: " + err.Error()})
		return
	}

	h.logger.Info("Cleared the statistics of the specified skill", zap.String("skill", skillName))
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Cleared the statistics of skill '%s'", skillName),
	})
}

// removeSkillFromRoles (reserved): roles no longer store skill bindings, so this is a no-op.
func (h *SkillsHandler) removeSkillFromRoles(skillName string) []string {
	_ = skillName
	return nil
}

// saveRolesConfig saves the role configuration to files (called from SkillsHandler)
func (h *SkillsHandler) saveRolesConfig() error {
	configDir := filepath.Dir(h.configPath)
	rolesDir := h.config.RolesDir
	if rolesDir == "" {
		rolesDir = "roles" // Default directory
	}

	// If it is a relative path, it is relative to the directory of the configuration file
	if !filepath.IsAbs(rolesDir) {
		rolesDir = filepath.Join(configDir, rolesDir)
	}

	// Ensure the directory exists
	if err := os.MkdirAll(rolesDir, 0755); err != nil {
		return fmt.Errorf("Failed to create the role directory: %w", err)
	}

	// Save each role to its own file
	if h.config.Roles != nil {
		for roleName, role := range h.config.Roles {
			// Ensure the role name is set correctly
			if role.Name == "" {
				role.Name = roleName
			}

			// Use the role name as the file name (sanitized, to avoid special characters)
			safeFileName := sanitizeRoleFileName(role.Name)
			roleFile := filepath.Join(rolesDir, safeFileName+".yaml")

			// Serialize the role configuration to YAML
			roleData, err := yaml.Marshal(&role)
			if err != nil {
				h.logger.Error("Failed to serialize the role configuration", zap.String("role", roleName), zap.Error(err))
				continue
			}

			// Handle the icon field: icon values containing \U must be wrapped in quotes (YAML needs quotes to parse Unicode escapes correctly)
			roleDataStr := string(roleData)
			if role.Icon != "" && strings.HasPrefix(role.Icon, "\\U") {
				// Match icon: \UXXXXXXXX format (without quotes), excluding values that already have quotes
				re := regexp.MustCompile(`(?m)^(icon:\s+)(\\U[0-9A-F]{8})(\s*)$`)
				roleDataStr = re.ReplaceAllString(roleDataStr, `${1}"${2}"${3}`)
				roleData = []byte(roleDataStr)
			}

			// Write to file
			if err := os.WriteFile(roleFile, roleData, 0644); err != nil {
				h.logger.Error("Failed to save the role configuration file", zap.String("role", roleName), zap.String("file", roleFile), zap.Error(err))
				continue
			}

			h.logger.Info("Role configuration saved to file", zap.String("role", roleName), zap.String("file", roleFile))
		}
	}

	return nil
}

// sanitizeRoleFileName converts a role name into a safe file name
func sanitizeRoleFileName(name string) string {
	// Replace characters that may be unsafe
	replacer := map[rune]string{
		'/':  "_",
		'\\': "_",
		':':  "_",
		'*':  "_",
		'?':  "_",
		'"':  "_",
		'<':  "_",
		'>':  "_",
		'|':  "_",
		' ':  "_",
	}

	var result []rune
	for _, r := range name {
		if replacement, ok := replacer[r]; ok {
			result = append(result, []rune(replacement)...)
		} else {
			result = append(result, r)
		}
	}

	fileName := string(result)
	// If the file name is empty, use the default name
	if fileName == "" {
		fileName = "role"
	}

	return fileName
}

// isValidSkillName validates a skill directory name (consistent with the name field of Agent Skills: lowercase, digits, hyphens)
func isValidSkillName(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}
