package control

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeUMSnapshotStore struct {
	loadSnapshot UMSnapshot
	loadErr      error
	saveCalls    int
	saved        UMSnapshot
}

func (f *fakeUMSnapshotStore) Load() (UMSnapshot, error) {
	if f.loadErr != nil {
		return UMSnapshot{}, f.loadErr
	}
	return f.loadSnapshot, nil
}

func (f *fakeUMSnapshotStore) Save(snapshot UMSnapshot) error {
	f.saveCalls++
	f.saved = snapshot
	return nil
}

func TestLoadUMSnapshotForPostgresStoreSeedsOnlyFromExplicitMigrationPath(t *testing.T) {
	t.Setenv("UM_STORE_MIGRATION_JSON_PATH", filepath.Join(t.TempDir(), "um.json"))
	if err := os.WriteFile(os.Getenv("UM_STORE_MIGRATION_JSON_PATH"), []byte(`{
  "certified_devices": {
    "sales.ms.net|itest-control-1": {
      "UserID": "itest",
      "GroupName": "sales.ms.net",
      "DeviceID": "itest-control-1",
      "PubKeyHex": "abc123",
      "AuthedAt": "2026-01-01T00:00:00Z"
    }
  }
}`), 0o600); err != nil {
		t.Fatalf("write migration snapshot: %v", err)
	}

	store := &fakeUMSnapshotStore{loadSnapshot: UMSnapshot{}}
	snapshot, err := loadUMSnapshotForPostgresStore(store)
	if err != nil {
		t.Fatalf("loadUMSnapshotForPostgresStore returned error: %v", err)
	}
	if store.saveCalls != 1 {
		t.Fatalf("expected one save call, got %d", store.saveCalls)
	}
	if len(snapshot.CertifiedDevices) != 1 {
		t.Fatalf("expected one certified device, got %d", len(snapshot.CertifiedDevices))
	}
	if got := snapshot.CertifiedDevices["sales.ms.net|itest-control-1"].PubKeyHex; got != "abc123" {
		t.Fatalf("unexpected pub key hex %q", got)
	}
}

func TestLoadUMSnapshotForPostgresStoreKeepsExistingDBState(t *testing.T) {
	t.Setenv("UM_STORE_MIGRATION_JSON_PATH", filepath.Join(t.TempDir(), "um.json"))

	store := &fakeUMSnapshotStore{
		loadSnapshot: UMSnapshot{
			CertifiedDevices: map[string]UMAuthDevice{
				"sales.ms.net|itest-control-1": {
					GroupName: "sales.ms.net",
					DeviceID:  "itest-control-1",
					PubKeyHex: "from-db",
				},
			},
		},
	}

	snapshot, err := loadUMSnapshotForPostgresStore(store)
	if err != nil {
		t.Fatalf("loadUMSnapshotForPostgresStore returned error: %v", err)
	}
	if store.saveCalls != 0 {
		t.Fatalf("expected no save calls, got %d", store.saveCalls)
	}
	if got := snapshot.CertifiedDevices["sales.ms.net|itest-control-1"].PubKeyHex; got != "from-db" {
		t.Fatalf("unexpected pub key hex %q", got)
	}
}

func TestLoadUMSnapshotForPostgresStoreReturnsDBError(t *testing.T) {
	t.Setenv("UM_STORE_MIGRATION_JSON_PATH", filepath.Join(t.TempDir(), "um.json"))

	_, err := loadUMSnapshotForPostgresStore(&fakeUMSnapshotStore{loadErr: errors.New("boom")})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
