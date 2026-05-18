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

type GatewayPolicySnapshot struct {
	Epoch uint64 `json:"epoch"`
}

type JSONGatewayStore struct {
	path string
	mu   sync.Mutex
}

func NewJSONGatewayStore(path string) *JSONGatewayStore {
	return &JSONGatewayStore{path: path}
}

type JSONGatewayPolicyStore struct {
	path string
	mu   sync.Mutex
}

func NewJSONGatewayPolicyStore(path string) *JSONGatewayPolicyStore {
	return &JSONGatewayPolicyStore{path: path}
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

func (s *JSONGatewayPolicyStore) Load() (GatewayPolicySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return GatewayPolicySnapshot{}, nil
		}
		return GatewayPolicySnapshot{}, fmt.Errorf("read gateway policy json: %w", err)
	}
	var snapshot GatewayPolicySnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return GatewayPolicySnapshot{}, fmt.Errorf("unmarshal gateway policy json: %w", err)
	}
	return snapshot, nil
}

func (s *JSONGatewayPolicyStore) Save(snapshot GatewayPolicySnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("mkdir gateway policy json dir: %w", err)
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal gateway policy json: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write gateway policy json temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename gateway policy json temp file: %w", err)
	}
	return nil
}

func (s *JSONGatewayPolicyStore) NextEpoch() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var snapshot GatewayPolicySnapshot
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			return 0, fmt.Errorf("read gateway policy json: %w", err)
		}
	} else if err := json.Unmarshal(data, &snapshot); err != nil {
		return 0, fmt.Errorf("unmarshal gateway policy json: %w", err)
	}
	next := snapshot.Epoch + 1
	if next == 0 {
		return 0, fmt.Errorf("gateway policy epoch overflow")
	}
	snapshot.Epoch = next
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return 0, fmt.Errorf("mkdir gateway policy json dir: %w", err)
	}
	encoded, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshal gateway policy json: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o644); err != nil {
		return 0, fmt.Errorf("write gateway policy json temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return 0, fmt.Errorf("rename gateway policy json temp file: %w", err)
	}
	return next, nil
}
