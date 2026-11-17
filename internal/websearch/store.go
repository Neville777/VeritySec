package websearch

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// storedProvider is what is written to disk. Unlike Provider, it includes the key.
type storedProvider struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Order   int    `json:"order"`
	Key     string `json:"key"`
}

// NewStore loads provider settings from path, or creates the defaults if the file does not exist.
// The file is written with owner-only permissions because it holds API keys.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path, items: DefaultProviders()}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, s.saveLocked()
		}
		return nil, err
	}
	var saved []storedProvider
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}
	byID := map[string]storedProvider{}
	for _, p := range saved {
		byID[p.ID] = p
	}
	for i, d := range s.items {
		if p, ok := byID[d.ID]; ok {
			s.items[i].Key = p.Key
			s.items[i].Enabled = p.Enabled
			s.items[i].Order = p.Order
		}
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	records := make([]storedProvider, 0, len(s.items))
	for _, p := range s.items {
		records = append(records, storedProvider{ID: p.ID, Enabled: p.Enabled, Order: p.Order, Key: p.Key})
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
