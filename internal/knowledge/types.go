package knowledge

import (
	"encoding/json"
	"time"
)

// formatTime formats time in RFC3339 format; zero time returns an empty string
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// KnowledgeItem knowledge base item
type KnowledgeItem struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"` // risk type (folder name)
	Title     string    `json:"title"`    // title (file name)
	FilePath  string    `json:"filePath"` // file path
	Content   string    `json:"content"`  // file content
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// KnowledgeItemSummary knowledge base item summary (for lists; does not include full content)
type KnowledgeItemSummary struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	Title     string    `json:"title"`
	FilePath  string    `json:"filePath"`
	Content   string    `json:"content,omitempty"` // optional: content preview (if provided, usually only the first 150 characters)
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// MarshalJSON custom JSON serialization to ensure the time format is correct
func (k *KnowledgeItemSummary) MarshalJSON() ([]byte, error) {
	type Alias KnowledgeItemSummary
	aux := &struct {
		*Alias
		CreatedAt string `json:"createdAt"`
		UpdatedAt string `json:"updatedAt"`
	}{
		Alias: (*Alias)(k),
	}
	aux.CreatedAt = formatTime(k.CreatedAt)
	aux.UpdatedAt = formatTime(k.UpdatedAt)
	return json.Marshal(aux)
}

// MarshalJSON custom JSON serialization to ensure the time format is correct
func (k *KnowledgeItem) MarshalJSON() ([]byte, error) {
	type Alias KnowledgeItem
	aux := &struct {
		*Alias
		CreatedAt string `json:"createdAt"`
		UpdatedAt string `json:"updatedAt"`
	}{
		Alias: (*Alias)(k),
	}
	aux.CreatedAt = formatTime(k.CreatedAt)
	aux.UpdatedAt = formatTime(k.UpdatedAt)
	return json.Marshal(aux)
}

// KnowledgeChunk knowledge chunk (for vectorization)
type KnowledgeChunk struct {
	ID         string    `json:"id"`
	ItemID     string    `json:"itemId"`
	ChunkIndex int       `json:"chunkIndex"`
	ChunkText  string    `json:"chunkText"`
	Embedding  []float32 `json:"-"` // vector embedding; not serialized to JSON
	CreatedAt  time.Time `json:"createdAt"`
}

// RetrievalResult retrieval result
type RetrievalResult struct {
	Chunk      *KnowledgeChunk `json:"chunk"`
	Item       *KnowledgeItem  `json:"item"`
	Similarity float64         `json:"similarity"` // similarity score
	Score      float64         `json:"score"`      // same as Similarity: cosine similarity
}

// RetrievalLog retrieval log
type RetrievalLog struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversationId,omitempty"`
	MessageID      string    `json:"messageId,omitempty"`
	Query          string    `json:"query"`
	RiskType       string    `json:"riskType,omitempty"`
	RetrievedItems []string  `json:"retrievedItems"` // list of retrieved knowledge item IDs
	CreatedAt      time.Time `json:"createdAt"`
}

// MarshalJSON custom JSON serialization to ensure the time format is correct
func (r *RetrievalLog) MarshalJSON() ([]byte, error) {
	type Alias RetrievalLog
	return json.Marshal(&struct {
		*Alias
		CreatedAt string `json:"createdAt"`
	}{
		Alias:     (*Alias)(r),
		CreatedAt: formatTime(r.CreatedAt),
	})
}

// CategoryWithItems category and its knowledge items (for paginated by category)
type CategoryWithItems struct {
	Category  string                  `json:"category"`  // category name
	ItemCount int                     `json:"itemCount"` // total number of knowledge items under this category
	Items     []*KnowledgeItemSummary `json:"items"`     // list of knowledge items under this category
}

// SearchRequest search request
type SearchRequest struct {
	Query          string  `json:"query"`
	RiskType       string  `json:"riskType,omitempty"`       // optional: specify the risk type
	SubIndexFilter string  `json:"subIndexFilter,omitempty"` // optional: keep only rows whose sub_indexes contain this tag (including untagged legacy data)
	TopK           int     `json:"topK,omitempty"`           // return Top-K results, default 5
	Threshold      float64 `json:"threshold,omitempty"`      // similarity threshold, default 0.7
}
