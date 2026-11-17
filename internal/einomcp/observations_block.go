package einomcp

import (
	"fmt"
	"sort"
	"strings"

	"veritysec/internal/observations"
)

const (
	observationsOpen  = "\n[observations]\n"
	observationsClose = "\n[/observations]"
	// maxObservationValuesShown is how many observation values the agent sees inline.
	maxObservationValuesShown = 20
)

// FormatObservationBlock renders the compact observation list appended to a recorded tool result:
// "Observations: N (kinds: ...)" followed by the first 20 values. compactRecordedToolResult moves
// this block into the compact block; it is facts about the output, not conclusions.
func FormatObservationBlock(obs []observations.Observation) string {
	if len(obs) == 0 {
		return ""
	}
	kinds := map[string]int{}
	for _, o := range obs {
		kinds[o.Kind]++
	}
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, k := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", k, kinds[k]))
	}
	var b strings.Builder
	b.WriteString(observationsOpen)
	fmt.Fprintf(&b, "Observations: %d (kinds: %s)", len(obs), strings.Join(parts, ", "))
	for i, o := range obs {
		if i >= maxObservationValuesShown {
			break
		}
		v := o.Value
		if o.Subject != "" && o.Attribute != "" {
			v = o.Subject + " " + o.Attribute + ": " + o.Value
		} else if o.Attribute != "" {
			v = o.Attribute + ": " + o.Value
		}
		fmt.Fprintf(&b, "\n- [%s] %s", o.Kind, strings.ReplaceAll(v, "\n", " "))
	}
	b.WriteString(observationsClose)
	return b.String()
}
