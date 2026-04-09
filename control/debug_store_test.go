package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDebugSnapshotStoreSaveAndPrune(t *testing.T) {
	baseDir := t.TempDir()
	store := NewDebugSnapshotStore(baseDir, 2)

	result := DebugCollectResult{
		Group:             "sales.ms.net",
		Name:              "win10-node",
		DeviceID:          "dev-1",
		VirtualIP:         "10.26.0.6",
		SnapshotJSON:      "{\"ok\":true}",
		CollectedAtUnixMs: 1000,
	}
	firstPath, err := store.Save(result)
	if err != nil {
		t.Fatalf("save first snapshot: %v", err)
	}
	if _, err := os.Stat(firstPath); err != nil {
		t.Fatalf("stat first snapshot: %v", err)
	}

	result.CollectedAtUnixMs = 1001
	secondPath, err := store.Save(result)
	if err != nil {
		t.Fatalf("save second snapshot: %v", err)
	}
	result.CollectedAtUnixMs = 1002
	thirdPath, err := store.Save(result)
	if err != nil {
		t.Fatalf("save third snapshot: %v", err)
	}

	deviceDir := filepath.Dir(thirdPath)
	if _, err := os.Stat(filepath.Join(deviceDir, "latest.json")); err != nil {
		t.Fatalf("stat latest snapshot: %v", err)
	}
	if _, err := os.Stat(firstPath); !os.IsNotExist(err) {
		t.Fatalf("expected first snapshot pruned, got err=%v", err)
	}
	if _, err := os.Stat(secondPath); err != nil {
		t.Fatalf("stat second snapshot: %v", err)
	}
	if _, err := os.Stat(thirdPath); err != nil {
		t.Fatalf("stat third snapshot: %v", err)
	}
}
