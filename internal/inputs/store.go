package inputs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxContentBytes is the largest input accepted (25 MB).
const MaxContentBytes = 25 << 20

var (
	ErrTooLarge  = errors.New("inputs: content exceeds 25 MB")
	ErrBadID     = errors.New("inputs: invalid id")
	ErrBadRoot   = errors.New("inputs: root required")
	ErrEmptyData = errors.New("inputs: empty content")
)

// InputRecord describes a stored input. Authorization is not part of it.
type InputRecord struct {
	ID           string
	EngagementID string
	OriginalName string // sanitised, display only
	DetectedKind Kind
	MIME         string
	SHA256       string
	Size         int64
	StoragePath  string
	CreatedAt    time.Time
}

func validID(id string) bool {
	if id == "" || len(id) > 128 || id == "." || strings.Contains(id, "..") {
		return false
	}
	return !strings.ContainsAny(id, "/\\\x00") && !strings.ContainsFunc(id, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// Store writes content to <root>/inputs/<engagementID>/<id>.bin (mode 0600,
// create-only). The bytes are never executed, decompressed or parsed.
func Store(root, engagementID string, content []byte, claimedName string) (*InputRecord, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return storeWithID(root, engagementID, hex.EncodeToString(b[:]), content, claimedName)
}

func storeWithID(root, engagementID, id string, content []byte, claimedName string) (*InputRecord, error) {
	if root == "" {
		return nil, ErrBadRoot
	}
	if !validID(engagementID) || !validID(id) {
		return nil, ErrBadID
	}
	if len(content) > MaxContentBytes {
		return nil, ErrTooLarge
	}
	if len(content) == 0 {
		return nil, ErrEmptyData
	}
	dir := filepath.Join(root, "inputs", engagementID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("inputs: mkdir: %w", err)
	}
	p := filepath.Join(dir, id+".bin")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("inputs: create: %w", err)
	}
	_, werr := f.Write(content)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(p)
		return nil, fmt.Errorf("inputs: write: %v %v", werr, cerr)
	}
	det := Detect(content, claimedName)
	sum := sha256.Sum256(content)
	return &InputRecord{
		ID: id, EngagementID: engagementID, OriginalName: SanitizeFilename(claimedName),
		DetectedKind: det.Kind, MIME: det.MIME, SHA256: hex.EncodeToString(sum[:]),
		Size: int64(len(content)), StoragePath: p, CreatedAt: time.Now().UTC(),
	}, nil
}
