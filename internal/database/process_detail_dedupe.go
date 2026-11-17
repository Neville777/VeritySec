package database

import (
	"fmt"
	"strings"
)

// DedupeConsecutiveProcessDetails removes adjacent, semantically identical process details
// (it uses the raw JSON of the DB's data column as a fingerprint, avoiding instability from map serialization key ordering).
func DedupeConsecutiveProcessDetails(rows []ProcessDetail) []ProcessDetail {
	if len(rows) < 2 {
		return rows
	}
	out := make([]ProcessDetail, 0, len(rows))
	var lastKey string
	for _, d := range rows {
		key := processDetailRowKey(d)
		if len(out) > 0 && key != "" && key == lastKey {
			continue
		}
		out = append(out, d)
		lastKey = key
	}
	return out
}

func processDetailRowKey(d ProcessDetail) string {
	return fmt.Sprintf("%s\x00%s\x00%s", d.EventType, strings.TrimSpace(d.Message), d.Data)
}
