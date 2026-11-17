package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"veritysec/internal/database"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type KnowledgeGraphHandler struct {
	db     *database.DB
	logger *zap.Logger
}

func NewKnowledgeGraphHandler(db *database.DB, logger *zap.Logger) *KnowledgeGraphHandler {
	return &KnowledgeGraphHandler{db: db, logger: logger}
}

func (h *KnowledgeGraphHandler) ListNodes(c *gin.Context) {
	engID := c.Param("id")
	nodeType := c.Query("type")
	query := "SELECT id, node_type, label, data_json, discovered_by, created_at FROM knowledge_nodes WHERE engagement_id = ?"
	args := []interface{}{engID}
	if nodeType != "" {
		query += " AND node_type = ?"
		args = append(args, nodeType)
	}
	query += " ORDER BY created_at"
	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, nt, label, dataJSON, disc, created string
		if err := rows.Scan(&id, &nt, &label, &dataJSON, &disc, &created); err != nil {
			continue
		}
		var data interface{}
		_ = json.Unmarshal([]byte(dataJSON), &data)
		out = append(out, gin.H{"id": id, "node_type": nt, "label": label, "data": data, "discovered_by": disc, "created_at": created})
	}
	c.JSON(http.StatusOK, gin.H{"nodes": out})
}

func (h *KnowledgeGraphHandler) AddNode(c *gin.Context) {
	engID := c.Param("id")
	var req struct {
		NodeType     string      `json:"node_type"`
		Label        string      `json:"label"`
		Data         interface{} `json:"data"`
		DiscoveredBy string      `json:"discovered_by"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Label == "" || req.NodeType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "node_type and label required"})
		return
	}
	dataBytes, _ := json.Marshal(req.Data)
	if req.Data == nil {
		dataBytes = []byte("{}")
	}
	id := uuid.NewString()
	_, err := h.db.Exec(`INSERT INTO knowledge_nodes (id, engagement_id, node_type, label, data_json, discovered_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, engID, req.NodeType, req.Label, string(dataBytes), req.DiscoveredBy, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *KnowledgeGraphHandler) DeleteNode(c *gin.Context) {
	nodeID := c.Param("node_id")
	engID := c.Param("id")
	_, _ = h.db.Exec("DELETE FROM knowledge_edges WHERE (source_node_id = ? OR target_node_id = ?) AND engagement_id = ?", nodeID, nodeID, engID)
	_, err := h.db.Exec("DELETE FROM knowledge_nodes WHERE id = ? AND engagement_id = ?", nodeID, engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *KnowledgeGraphHandler) ListEdges(c *gin.Context) {
	engID := c.Param("id")
	rows, err := h.db.Query(`SELECT e.id, e.source_node_id, e.target_node_id, e.edge_type, e.data_json, e.created_at,
		COALESCE(sn.label,''), COALESCE(tn.label,'')
		FROM knowledge_edges e
		LEFT JOIN knowledge_nodes sn ON sn.id = e.source_node_id
		LEFT JOIN knowledge_nodes tn ON tn.id = e.target_node_id
		WHERE e.engagement_id = ? ORDER BY e.created_at`, engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []gin.H
	for rows.Next() {
		var id, src, tgt, et, dataJSON, created, srcLabel, tgtLabel string
		if err := rows.Scan(&id, &src, &tgt, &et, &dataJSON, &created, &srcLabel, &tgtLabel); err != nil {
			continue
		}
		var data interface{}
		_ = json.Unmarshal([]byte(dataJSON), &data)
		out = append(out, gin.H{
			"id": id, "source_node_id": src, "target_node_id": tgt, "edge_type": et,
			"data": data, "created_at": created, "source_label": srcLabel, "target_label": tgtLabel,
		})
	}
	c.JSON(http.StatusOK, gin.H{"edges": out})
}

func (h *KnowledgeGraphHandler) AddEdge(c *gin.Context) {
	engID := c.Param("id")
	var req struct {
		SourceNodeID string      `json:"source_node_id"`
		TargetNodeID string      `json:"target_node_id"`
		EdgeType     string      `json:"edge_type"`
		Data         interface{} `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.SourceNodeID == "" || req.TargetNodeID == "" || req.EdgeType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_node_id, target_node_id, and edge_type required"})
		return
	}
	dataBytes, _ := json.Marshal(req.Data)
	if req.Data == nil {
		dataBytes = []byte("{}")
	}
	id := uuid.NewString()
	_, err := h.db.Exec(`INSERT INTO knowledge_edges (id, engagement_id, source_node_id, target_node_id, edge_type, data_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, engID, req.SourceNodeID, req.TargetNodeID, req.EdgeType, string(dataBytes), time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *KnowledgeGraphHandler) DeleteEdge(c *gin.Context) {
	edgeID := c.Param("edge_id")
	engID := c.Param("id")
	_, err := h.db.Exec("DELETE FROM knowledge_edges WHERE id = ? AND engagement_id = ?", edgeID, engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *KnowledgeGraphHandler) GetGraph(c *gin.Context) {
	engID := c.Param("id")
	nodeRows, err := h.db.Query("SELECT id, node_type, label, data_json FROM knowledge_nodes WHERE engagement_id = ?", engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer nodeRows.Close()
	var nodes []gin.H
	for nodeRows.Next() {
		var id, nt, label, dataJSON string
		if err := nodeRows.Scan(&id, &nt, &label, &dataJSON); err != nil {
			continue
		}
		var data interface{}
		_ = json.Unmarshal([]byte(dataJSON), &data)
		nodes = append(nodes, gin.H{"id": id, "type": nt, "label": label, "data": data})
	}
	edgeRows, err := h.db.Query("SELECT id, source_node_id, target_node_id, edge_type, data_json FROM knowledge_edges WHERE engagement_id = ?", engID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer edgeRows.Close()
	var edges []gin.H
	for edgeRows.Next() {
		var id, src, tgt, et, dataJSON string
		if err := edgeRows.Scan(&id, &src, &tgt, &et, &dataJSON); err != nil {
			continue
		}
		var data interface{}
		_ = json.Unmarshal([]byte(dataJSON), &data)
		edges = append(edges, gin.H{"id": id, "source": src, "target": tgt, "type": et, "data": data})
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges})
}
