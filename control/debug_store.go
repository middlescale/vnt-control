package control

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type DebugSnapshotStore struct {
	baseDir       string
	keepPerDevice int
	mu            sync.Mutex
}

type DebugWatchSession struct {
	WatchID         uint64
	UserID          string
	Group           string
	Name            string
	DeviceID        string
	VirtualIP       string
	StartedAtUnixMs int64
	ExpireAtUnixMs  int64
	SessionDir      string
	EventsPath      string
}

func NewDebugSnapshotStore(baseDir string, keepPerDevice int) *DebugSnapshotStore {
	if keepPerDevice <= 0 {
		keepPerDevice = 20
	}
	return &DebugSnapshotStore{
		baseDir:       baseDir,
		keepPerDevice: keepPerDevice,
	}
}

func (s *DebugSnapshotStore) Save(result DebugCollectResult) (string, error) {
	if s == nil || strings.TrimSpace(s.baseDir) == "" {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceDir := filepath.Join(
		s.baseDir,
		sanitizeDebugPathPart(result.Group, "unknown-group"),
		fmt.Sprintf(
			"%s__%s",
			sanitizeDebugPathPart(result.Name, "unknown-name"),
			sanitizeDebugPathPart(firstNonEmptyDebug(result.DeviceID, result.VirtualIP), "unknown-device"),
		),
	)
	if err := os.MkdirAll(deviceDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir debug snapshot dir: %w", err)
	}

	collectedAt := result.CollectedAtUnixMs
	if collectedAt <= 0 {
		collectedAt = time.Now().UnixMilli()
	}
	fileName := fmt.Sprintf(
		"%d__%s.json",
		collectedAt,
		sanitizeDebugPathPart(result.VirtualIP, "unknown-ip"),
	)
	filePath := filepath.Join(deviceDir, fileName)
	if err := writeAtomicFile(filePath, []byte(result.SnapshotJSON)); err != nil {
		return "", err
	}
	if err := writeAtomicFile(filepath.Join(deviceDir, "latest.json"), []byte(result.SnapshotJSON)); err != nil {
		return "", err
	}
	if err := s.pruneDeviceDir(deviceDir); err != nil {
		return "", err
	}
	return filePath, nil
}

func (s *DebugSnapshotStore) StartWatch(session DebugWatchSession) (DebugWatchSession, error) {
	if s == nil || strings.TrimSpace(s.baseDir) == "" {
		return session, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deviceDir := filepath.Join(
		s.baseDir,
		"watch",
		sanitizeDebugPathPart(session.Group, "unknown-group"),
		fmt.Sprintf(
			"%s__%s",
			sanitizeDebugPathPart(session.Name, "unknown-name"),
			sanitizeDebugPathPart(firstNonEmptyDebug(session.DeviceID, session.VirtualIP), "unknown-device"),
		),
	)
	sessionDir := filepath.Join(deviceDir, fmt.Sprintf("watch-%d", session.WatchID))
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return session, fmt.Errorf("mkdir debug watch dir: %w", err)
	}
	session.SessionDir = sessionDir
	session.EventsPath = filepath.Join(sessionDir, "events.jsonl")
	metadataPath := filepath.Join(sessionDir, "metadata.json")
	metadata := fmt.Sprintf(
		"{\"watch_id\":%d,\"user_id\":%q,\"group\":%q,\"name\":%q,\"device_id\":%q,\"virtual_ip\":%q,\"started_at_unix_ms\":%d,\"expire_at_unix_ms\":%d}\n",
		session.WatchID,
		session.UserID,
		session.Group,
		session.Name,
		session.DeviceID,
		session.VirtualIP,
		session.StartedAtUnixMs,
		session.ExpireAtUnixMs,
	)
	if err := writeAtomicFile(metadataPath, []byte(metadata)); err != nil {
		return session, err
	}
	if err := writeAtomicFile(filepath.Join(sessionDir, "latest-watch.json"), []byte(metadata)); err != nil {
		return session, err
	}
	if err := s.pruneWatchDeviceDir(deviceDir); err != nil {
		return session, err
	}
	return session, nil
}

func (s *DebugSnapshotStore) AppendWatchEvent(session DebugWatchSession, line []byte) error {
	if s == nil || session.EventsPath == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(session.EventsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open debug watch events: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(line); err != nil {
		return fmt.Errorf("append debug watch event: %w", err)
	}
	return nil
}

func (s *DebugSnapshotStore) FinishWatch(session DebugWatchSession, stoppedAtUnixMs int64) error {
	if s == nil || session.SessionDir == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	content := fmt.Sprintf("{\"watch_id\":%d,\"stopped_at_unix_ms\":%d}\n", session.WatchID, stoppedAtUnixMs)
	return writeAtomicFile(filepath.Join(session.SessionDir, "stopped.json"), []byte(content))
}

func (s *DebugSnapshotStore) pruneDeviceDir(deviceDir string) error {
	entries, err := os.ReadDir(deviceDir)
	if err != nil {
		return fmt.Errorf("read debug snapshot dir: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "latest.json" || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)
	for len(files) > s.keepPerDevice {
		removeName := files[0]
		files = files[1:]
		if err := os.Remove(filepath.Join(deviceDir, removeName)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old debug snapshot %s: %w", removeName, err)
		}
	}
	return nil
}

func (s *DebugSnapshotStore) pruneWatchDeviceDir(deviceDir string) error {
	entries, err := os.ReadDir(deviceDir)
	if err != nil {
		return fmt.Errorf("read debug watch dir: %w", err)
	}
	dirs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "watch-") {
			dirs = append(dirs, entry.Name())
		}
	}
	sort.Strings(dirs)
	for len(dirs) > s.keepPerDevice {
		removeName := dirs[0]
		dirs = dirs[1:]
		if err := os.RemoveAll(filepath.Join(deviceDir, removeName)); err != nil {
			return fmt.Errorf("remove old debug watch %s: %w", removeName, err)
		}
	}
	return nil
}

func writeAtomicFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write debug snapshot temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename debug snapshot temp file: %w", err)
	}
	return nil
}

func sanitizeDebugPathPart(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	value = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, value)
	value = strings.Trim(value, "._-")
	if value == "" {
		return fallback
	}
	return value
}

func firstNonEmptyDebug(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
