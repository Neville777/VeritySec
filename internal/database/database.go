package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

const (
	// WAL permits concurrent readers but only one writer; keep the pool modest.
	sqliteMaxOpenConns  = 8
	sqliteMaxIdleConns  = 4
	sqliteBusyTimeoutMS = 30000
	// Auto-checkpoint trigger threshold in pages (default 1000 pages, ~4MB @ 4KB/page).
	sqliteWALAutoCheckpointPages = 1000
	// Caps the WAL target size to prevent unbounded growth in abnormal scenarios (256MB).
	sqliteJournalSizeLimitBytes = 256 * 1024 * 1024
	// Runs a PASSIVE checkpoint periodically to smoothly reclaim the WAL.
	sqlitePassiveCheckpointInterval = 300 * time.Second
)

func sqliteOpenDSN(path string) string {
	// Reserve the writer at Begin, before read-modify-write transactions take a
	// snapshot. DEFERRED upgrades may fail immediately without busy_timeout.
	// Let SQLite wait once; retrying after each timeout multiplies lock latency.
	return fmt.Sprintf("%s?_journal_mode=WAL&_foreign_keys=1&_busy_timeout=%d&_synchronous=NORMAL&_txlock=immediate", path, sqliteBusyTimeoutMS)
}

// configureDBPool sets up the SQLite connection pool, keeping a modest number of connections for concurrent WAL reads.
func configureDBPool(db *sql.DB) {
	db.SetMaxOpenConns(sqliteMaxOpenConns)
	db.SetMaxIdleConns(sqliteMaxIdleConns)
	db.SetConnMaxLifetime(30 * time.Minute)
}

// configureSQLitePragmas tunes WAL reclamation behavior to reduce the risk of long-term -wal file growth.
func configureSQLitePragmas(db *sql.DB) error {
	if _, err := db.Exec(fmt.Sprintf("PRAGMA wal_autocheckpoint=%d", sqliteWALAutoCheckpointPages)); err != nil {
		return fmt.Errorf("failed to set wal_autocheckpoint: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA journal_size_limit=%d", sqliteJournalSizeLimitBytes)); err != nil {
		return fmt.Errorf("failed to set journal_size_limit: %w", err)
	}
	return nil
}

// DB is a database connection
type DB struct {
	*sql.DB
	logger                   *zap.Logger
	conversationArtifactsDir string
	einoPlantaskBaseDir      string // skills_dir + plantask_rel_dir (per-conversation subdirs)
	einoCheckpointBaseDir    string // checkpoint_dir root (per-conversation subdirs)
	einoReductionRootDir     string // reduction_root_dir or default tmp/reduction (conversations/<id> subdirs)
	einoWorkspaceRootDir     string // workspace_root_dir or default tmp/workspace (projects|conversations/<id> subdirs)
	chatUploadsDir           string // chat_uploads root (<date>/<conversationID> subdirs)
	checkpointLoopName       string
	checkpointStop           chan struct{}
	checkpointDone           chan struct{}
	closeOnce                sync.Once
	closeErr                 error
	vulnerabilityCreatedHook func(*Vulnerability)
}

// startPassiveCheckpointLoop starts the background PASSIVE checkpoint loop.
func (db *DB) startPassiveCheckpointLoop(name string) {
	if sqlitePassiveCheckpointInterval <= 0 || db == nil || db.DB == nil {
		return
	}
	db.checkpointLoopName = strings.TrimSpace(name)
	db.checkpointStop = make(chan struct{})
	db.checkpointDone = make(chan struct{})

	go func() {
		defer close(db.checkpointDone)
		ticker := time.NewTicker(sqlitePassiveCheckpointInterval)
		defer ticker.Stop()

		// Try once right after startup to reclaim any existing WAL backlog as soon as possible.
		db.runPassiveCheckpoint("startup")
		for {
			select {
			case <-db.checkpointStop:
				return
			case <-ticker.C:
				db.runPassiveCheckpoint("ticker")
			}
		}
	}()
}

// runPassiveCheckpoint runs one PRAGMA wal_checkpoint(PASSIVE).
func (db *DB) runPassiveCheckpoint(trigger string) {
	if db == nil || db.DB == nil {
		return
	}
	startAt := time.Now()
	var busy, logFrames, checkpointed int
	err := db.QueryRow("PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &logFrames, &checkpointed)
	if db.logger == nil {
		return
	}
	fields := []zap.Field{
		zap.String("db", db.checkpointLoopName),
		zap.String("trigger", trigger),
		zap.Int("busy", busy),
		zap.Int("log_frames", logFrames),
		zap.Int("checkpointed_frames", checkpointed),
		zap.Int64("elapsed_ms", time.Since(startAt).Milliseconds()),
	}
	if err != nil {
		db.logger.Warn("SQLite PASSIVE checkpoint completed (failed)",
			append(fields, zap.Error(err))...,
		)
		return
	}
	if busy > 0 {
		db.logger.Debug("SQLite PASSIVE checkpoint completed (partial progress)", fields...)
		return
	}
	db.logger.Debug("SQLite PASSIVE checkpoint completed (success)", fields...)
}

// NewDB creates a database connection
func NewDB(dbPath string, logger *zap.Logger) (*DB, error) {
	db, err := sql.Open("sqlite3", sqliteOpenDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	configureDBPool(db)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if err := configureSQLitePragmas(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to configure database PRAGMA: %w", err)
	}

	database := &DB{
		DB:     db,
		logger: logger,
	}
	// Keep conversation-scoped artifacts near database files, so cleanup can follow conversation lifecycle.
	baseDir := filepath.Join(filepath.Dir(dbPath), "conversation_artifacts")
	if mkErr := os.MkdirAll(baseDir, 0o755); mkErr == nil {
		database.conversationArtifactsDir = baseDir
	} else if logger != nil {
		logger.Warn("failed to create conversation artifacts directory", zap.String("dir", baseDir), zap.Error(mkErr))
	}

	// Initialize tables
	if err := database.initTables(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}
	if err := database.initAgentRuns(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := database.migrateLegacyToolGuardBlocks(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to migrate legacy security block records: %w", err)
	}
	database.startPassiveCheckpointLoop("conversations")

	return database, nil
}

// SetEinoConversationDirs configures best-effort filesystem cleanup on DeleteConversation.
// plantaskBase is skills_root/plantask_rel (no conversation id); checkpointBase is checkpoint_dir root.
// reductionRoot is reduction_root_dir from config; empty uses tmp/reduction (conversation-scoped subdirs only).
// workspaceRoot is agent.workspace_root_dir from config; empty uses tmp/workspace.
func (db *DB) SetEinoConversationDirs(plantaskBase, checkpointBase, reductionRoot, workspaceRoot string) {
	if db == nil {
		return
	}
	db.einoPlantaskBaseDir = strings.TrimSpace(plantaskBase)
	db.einoCheckpointBaseDir = strings.TrimSpace(checkpointBase)
	db.einoReductionRootDir = strings.TrimSpace(reductionRoot)
	db.einoWorkspaceRootDir = strings.TrimSpace(workspaceRoot)
}

// SetChatUploadsDir configures the chat_uploads root so DeleteConversation can remove
// uploaded attachment files. Their chat_upload_artifacts rows already disappear via
// ON DELETE CASCADE; without this the files themselves would linger forever.
func (db *DB) SetChatUploadsDir(dir string) {
	if db == nil {
		return
	}
	db.chatUploadsDir = strings.TrimSpace(dir)
}

// initTables initializes the database tables
func (db *DB) initTables() error {
	if err := db.reconcileSchema(applicationSchema); err != nil {
		return err
	}
	// Data migrations are separate from schema repair.
	if _, err := db.Exec("UPDATE messages SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = ''"); err != nil {
		return fmt.Errorf("failed to backfill message update time: %w", err)
	}
	// Findings that predate source_status (column default 'unlinked') but already carry tool-origin
	// evidence are genuinely linked.
	if _, err := db.Exec(`UPDATE vulnerabilities SET source_status = 'linked'
		WHERE source_status = 'unlinked' AND id IN (SELECT finding_id FROM evidence WHERE origin = 'tool' AND finding_id IS NOT NULL)`); err != nil {
		return fmt.Errorf("failed to backfill vulnerability source status: %w", err)
	}
	if err := db.migrateVulnerabilitiesConversationFK(); err != nil {
		return fmt.Errorf("failed to migrate vulnerability conversation foreign key: %w", err)
	}
	if err := db.BackfillModelTokenUsageFromProcessDetails(); err != nil {
		return fmt.Errorf("failed to backfill model token usage: %w", err)
	}
	db.logger.Debug("database schema check and reconciliation complete")
	return nil
}

// NewKnowledgeDB creates a knowledge base database connection (containing only knowledge-base-related tables)
func NewKnowledgeDB(dbPath string, logger *zap.Logger) (*DB, error) {
	sqlDB, err := sql.Open("sqlite3", sqliteOpenDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open knowledge base database: %w", err)
	}

	configureDBPool(sqlDB)

	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to connect to knowledge base database: %w", err)
	}
	if err := configureSQLitePragmas(sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to configure knowledge base database PRAGMA: %w", err)
	}

	database := &DB{
		DB:     sqlDB,
		logger: logger,
	}

	// Initialize knowledge base tables
	if err := database.initKnowledgeTables(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to initialize knowledge base tables: %w", err)
	}
	database.startPassiveCheckpointLoop("knowledge")

	return database, nil
}

// initKnowledgeTables initializes the knowledge base database tables (containing only knowledge-base-related tables)
func (db *DB) initKnowledgeTables() error {
	if err := db.reconcileSchema(knowledgeSchema); err != nil {
		return err
	}
	db.logger.Info("database schema check and reconciliation complete")
	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	db.closeOnce.Do(func() {
		if db.checkpointStop != nil {
			close(db.checkpointStop)
			if db.checkpointDone != nil {
				<-db.checkpointDone
			}
		}
		if db.DB != nil {
			db.closeErr = db.DB.Close()
		}
	})
	return db.closeErr
}
