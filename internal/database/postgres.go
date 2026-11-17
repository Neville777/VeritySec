package database

import (
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func IsPostgresMode() bool {
	return os.Getenv("DATABASE_URL") != ""
}

func NewPostgresDB(logger *zap.Logger) (*DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL not set")
	}

	if !strings.Contains(dsn, "sslmode=") {
		if strings.Contains(dsn, "?") {
			dsn += "&sslmode=require"
		} else {
			dsn += "?sslmode=require"
		}
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres: %w", err)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(10 * time.Minute)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	database := &DB{
		DB:     db,
		logger: logger,
	}

	if err := database.initPostgresTables(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize postgres tables: %w", err)
	}

	logger.Info("connected to PostgreSQL (Neon)")
	return database, nil
}

func (db *DB) initPostgresTables() error {
	pgSchema := sqliteToPg(applicationSchema)
	statements := splitSQLStatements(pgSchema)
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			if isAlreadyExistsError(err) {
				continue
			}
			db.logger.Warn("postgres schema statement failed (non-fatal)", zap.String("stmt", truncateSQL(stmt, 120)), zap.Error(err))
		}
	}
	return nil
}

func sqliteToPg(schema string) string {
	s := schema

	// AUTOINCREMENT → GENERATED ALWAYS AS IDENTITY or SERIAL pattern
	// SQLite: INTEGER PRIMARY KEY AUTOINCREMENT → PG: SERIAL PRIMARY KEY
	re := regexp.MustCompile(`(?i)\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b`)
	s = re.ReplaceAllString(s, "SERIAL PRIMARY KEY")

	// TEXT PRIMARY KEY stays
	// DATETIME → TIMESTAMPTZ
	s = regexp.MustCompile(`(?i)\bDATETIME\b`).ReplaceAllString(s, "TIMESTAMPTZ")

	// BOOLEAN → BOOLEAN (already compatible)
	// INTEGER → INTEGER (already compatible)
	// REAL → DOUBLE PRECISION
	s = regexp.MustCompile(`(?i)\bREAL\b`).ReplaceAllString(s, "DOUBLE PRECISION")

	// datetime('now') → NOW()
	s = regexp.MustCompile(`(?i)datetime\('now'\)`).ReplaceAllString(s, "NOW()")
	s = regexp.MustCompile(`(?i)datetime\('now',\s*'([^']+)'\)`).ReplaceAllString(s, "NOW() + INTERVAL '$1'")

	// strftime('%s', col) → EXTRACT(EPOCH FROM col)
	s = regexp.MustCompile(`(?i)strftime\('%s',\s*([^)]+)\)`).ReplaceAllString(s, "EXTRACT(EPOCH FROM $1)")

	// GROUP_CONCAT → STRING_AGG
	s = regexp.MustCompile(`(?i)GROUP_CONCAT\(([^,)]+)\)`).ReplaceAllString(s, "STRING_AGG($1, ',')")
	s = regexp.MustCompile(`(?i)GROUP_CONCAT\(([^,]+),\s*'([^']+)'\)`).ReplaceAllString(s, "STRING_AGG($1, '$2')")

	// GLOB → LIKE (approximate; GLOB uses * and ?, LIKE uses % and _)
	s = regexp.MustCompile(`(?i)\bGLOB\b`).ReplaceAllString(s, "LIKE")

	// Remove IF NOT EXISTS from CREATE INDEX (PG supports it, but be safe)
	// Actually PG supports IF NOT EXISTS on CREATE INDEX, so leave it

	// Remove PRAGMA statements
	s = regexp.MustCompile(`(?im)^PRAGMA [^;]+;?\s*$`).ReplaceAllString(s, "")

	// SQLite-specific: ON CONFLICT IGNORE → ON CONFLICT DO NOTHING
	s = strings.ReplaceAll(s, "ON CONFLICT IGNORE", "ON CONFLICT DO NOTHING")

	// INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE (needs manual handling per-query)
	// INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
	s = regexp.MustCompile(`(?i)INSERT\s+OR\s+IGNORE\s+INTO`).ReplaceAllString(s, "INSERT INTO")
	s = regexp.MustCompile(`(?i)INSERT\s+OR\s+REPLACE\s+INTO`).ReplaceAllString(s, "INSERT INTO")

	return s
}

func splitSQLStatements(sql string) []string {
	var stmts []string
	var current strings.Builder
	depth := 0
	inString := false
	prev := rune(0)

	for _, ch := range sql {
		if ch == '\'' && prev != '\\' {
			inString = !inString
		}
		if !inString {
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
			}
			if ch == ';' && depth <= 0 {
				s := strings.TrimSpace(current.String())
				if s != "" {
					stmts = append(stmts, s)
				}
				current.Reset()
				depth = 0
				prev = ch
				continue
			}
		}
		current.WriteRune(ch)
		prev = ch
	}
	if s := strings.TrimSpace(current.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

func isAlreadyExistsError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate key")
}

func truncateSQL(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
