package database

import (
	"fmt"
	"os"
	"strings"
)

// RewritePlaceholders converts SQLite ? placeholders to PostgreSQL $N style
// when running in Postgres mode. In SQLite mode it's a no-op.
func RewritePlaceholders(query string) string {
	if !IsPostgresMode() {
		return query
	}
	return rewriteQuestionMarks(query)
}

func rewriteQuestionMarks(query string) string {
	var out strings.Builder
	n := 1
	inString := false
	for i := 0; i < len(query); i++ {
		ch := query[i]
		if ch == '\'' {
			inString = !inString
			out.WriteByte(ch)
			continue
		}
		if !inString && ch == '?' {
			out.WriteString(fmt.Sprintf("$%d", n))
			n++
		} else {
			out.WriteByte(ch)
		}
	}
	return out.String()
}

// DatetimeNow returns the SQL expression for current time.
func DatetimeNow() string {
	if IsPostgresMode() {
		return "NOW()"
	}
	return "datetime('now')"
}

// DatetimeOffset returns SQL for now +/- an interval like '-7 days'.
func DatetimeOffset(offset string) string {
	if IsPostgresMode() {
		return fmt.Sprintf("NOW() + INTERVAL '%s'", offset)
	}
	return fmt.Sprintf("datetime('now', '%s')", offset)
}

// UpsertSuffix returns the conflict handling suffix for Postgres vs SQLite.
func UpsertSuffix(conflictCol string, updateCols []string) string {
	if IsPostgresMode() {
		sets := make([]string, len(updateCols))
		for i, col := range updateCols {
			sets[i] = fmt.Sprintf("%s = EXCLUDED.%s", col, col)
		}
		return fmt.Sprintf("ON CONFLICT(%s) DO UPDATE SET %s", conflictCol, strings.Join(sets, ", "))
	}
	return ""
}

// ILike returns a case-insensitive LIKE expression.
func ILike() string {
	if IsPostgresMode() {
		return "ILIKE"
	}
	return "LIKE"
}

// GroupConcat returns the aggregate function for string concatenation.
func GroupConcat(col string, sep string) string {
	if IsPostgresMode() {
		return fmt.Sprintf("STRING_AGG(%s, '%s')", col, sep)
	}
	if sep == "," {
		return fmt.Sprintf("GROUP_CONCAT(%s)", col)
	}
	return fmt.Sprintf("GROUP_CONCAT(%s, '%s')", col, sep)
}

// ConcatWS returns a string concatenation call that works on both DBs.
func ConcatWS(sep string, cols ...string) string {
	if IsPostgresMode() {
		return fmt.Sprintf("CONCAT_WS('%s', %s)", sep, strings.Join(cols, ", "))
	}
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = fmt.Sprintf("COALESCE(%s, '')", c)
	}
	return strings.Join(parts, " || '"+sep+"' || ")
}

// DBType returns "postgres" or "sqlite" for conditional logic.
func DBType() string {
	if os.Getenv("DATABASE_URL") != "" {
		return "postgres"
	}
	return "sqlite"
}
