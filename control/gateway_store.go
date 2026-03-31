package control

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type GatewayStoreSnapshot struct {
	Approved map[string]string `json:"approved"`
}

type JSONGatewayStore struct {
	path string
	mu   sync.Mutex
}

func NewJSONGatewayStore(path string) *JSONGatewayStore {
	return &JSONGatewayStore{path: path}
}

func (s *JSONGatewayStore) Load() (GatewayStoreSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return GatewayStoreSnapshot{}, nil
		}
		return GatewayStoreSnapshot{}, fmt.Errorf("read gateway json: %w", err)
	}
	var snapshot GatewayStoreSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return GatewayStoreSnapshot{}, fmt.Errorf("unmarshal gateway json: %w", err)
	}
	return snapshot, nil
}

func (s *JSONGatewayStore) Save(snapshot GatewayStoreSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("mkdir gateway json dir: %w", err)
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal gateway json: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write gateway json temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename gateway json temp file: %w", err)
	}
	return nil
}
