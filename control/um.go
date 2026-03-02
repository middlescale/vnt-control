package control

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type UMUser struct {
	UserID    string
	Name      string
	CreatedAt time.Time
}

type UMEnrollment struct {
	Code      string
	UserID    string
	ExpireAt  time.Time
	Used      bool
	CreatedAt time.Time
}

type UMDevice struct {
	UserID      string
	DeviceID    string
	PubKeyAlg   string
	PubKeyHex   string
	CreatedAt   time.Time
	LastBoundAt time.Time
}

type UMPolicy struct {
	UserID                  string
	GroupName               string
	UserExpireAtUnixMs      int64
	UserGracePeriodSeconds  int64
	AllowP2P                bool
	AllowRelay              bool
	MaxDevices              int
	EnrollmentTTLSeconds    int64
	GatewayTicketTTLSeconds int64
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

type UMDeviceTicket struct {
	Ticket    string
	UserID    string
	GroupName string
	ExpireAt  time.Time
	Used      bool
}

type UMAuthDevice struct {
	UserID    string
	GroupName string
	DeviceID  string
	AuthedAt  time.Time
}

type UserManager struct {
	mu             sync.RWMutex
	store          UMStore
	userSeq        atomic.Uint64
	enrollmentSeq  atomic.Uint64
	users          map[string]UMUser
	policies       map[string]UMPolicy
	enrollments    map[string]UMEnrollment
	deviceByPubKey map[string]UMDevice
	authedDevices  map[string]UMAuthDevice
	deviceTickets  map[string]UMDeviceTicket
}

func NewUserManager() *UserManager {
	m := &UserManager{
		users:          make(map[string]UMUser),
		policies:       make(map[string]UMPolicy),
		enrollments:    make(map[string]UMEnrollment),
		deviceByPubKey: make(map[string]UMDevice),
		authedDevices:  make(map[string]UMAuthDevice),
		deviceTickets:  make(map[string]UMDeviceTicket),
	}
	return m
}

func NewUserManagerWithStore(store UMStore) (*UserManager, error) {
	m := NewUserManager()
	m.store = store
	snapshot, err := store.Load()
	if err != nil {
		return nil, err
	}
	m.restore(snapshot)
	return m, nil
}

func (m *UserManager) CreateUser(name string) (UMUser, error) {
	if name == "" {
		return UMUser{}, fmt.Errorf("user name is empty")
	}
	id := fmt.Sprintf("u-%d", m.userSeq.Add(1))
	user := UMUser{
		UserID:    id,
		Name:      name,
		CreatedAt: time.Now(),
	}
	m.mu.Lock()
	m.users[id] = user
	m.policies[id] = m.generateBasicPolicyLocked(id)
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return UMUser{}, err
	}
	return user, nil
}

func (m *UserManager) CreateEnrollment(userID string, ttl time.Duration) (UMEnrollment, error) {
	if ttl <= 0 {
		return UMEnrollment{}, fmt.Errorf("invalid ttl")
	}
	m.mu.RLock()
	_, exists := m.users[userID]
	m.mu.RUnlock()
	if !exists {
		return UMEnrollment{}, fmt.Errorf("user not found")
	}
	seq := m.enrollmentSeq.Add(1)
	code := fmt.Sprintf("enr-%d-%d", time.Now().UnixNano(), seq)
	enrollment := UMEnrollment{
		Code:      code,
		UserID:    userID,
		ExpireAt:  time.Now().Add(ttl),
		Used:      false,
		CreatedAt: time.Now(),
	}
	m.mu.Lock()
	m.enrollments[code] = enrollment
	err := m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return UMEnrollment{}, err
	}
	return enrollment, nil
}

func (m *UserManager) BindDeviceByEnrollment(code string, deviceID string, pubKey []byte, pubKeyAlg string) (UMDevice, error) {
	if code == "" {
		return UMDevice{}, fmt.Errorf("enrollment code is empty")
	}
	if deviceID == "" {
		return UMDevice{}, fmt.Errorf("device_id is empty")
	}
	if len(pubKey) == 0 {
		return UMDevice{}, fmt.Errorf("device public key is empty")
	}
	if pubKeyAlg == "" {
		return UMDevice{}, fmt.Errorf("device public key algorithm is empty")
	}
	now := time.Now()
	pubKeyHex := toPubKeyHex(pubKey, pubKeyAlg)

	m.mu.Lock()
	defer m.mu.Unlock()
	enrollment, ok := m.enrollments[code]
	if !ok {
		return UMDevice{}, fmt.Errorf("enrollment not found")
	}
	if enrollment.Used {
		return UMDevice{}, fmt.Errorf("enrollment already used")
	}
	if now.After(enrollment.ExpireAt) {
		return UMDevice{}, fmt.Errorf("enrollment expired")
	}
	if _, exists := m.users[enrollment.UserID]; !exists {
		return UMDevice{}, fmt.Errorf("user not found")
	}
	if existing, ok := m.deviceByPubKey[pubKeyHex]; ok && existing.UserID != enrollment.UserID {
		return UMDevice{}, fmt.Errorf("device key already bound to another user")
	}
	device := UMDevice{
		UserID:      enrollment.UserID,
		DeviceID:    deviceID,
		PubKeyAlg:   pubKeyAlg,
		PubKeyHex:   pubKeyHex,
		CreatedAt:   now,
		LastBoundAt: now,
	}
	m.deviceByPubKey[pubKeyHex] = device
	enrollment.Used = true
	m.enrollments[code] = enrollment
	if err := m.saveLocked(); err != nil {
		return UMDevice{}, err
	}
	return device, nil
}

func (m *UserManager) FindUserByDevicePubKey(pubKey []byte, pubKeyAlg string) (UMUser, bool) {
	pubKeyHex := toPubKeyHex(pubKey, pubKeyAlg)
	m.mu.RLock()
	defer m.mu.RUnlock()
	device, ok := m.deviceByPubKey[pubKeyHex]
	if !ok {
		return UMUser{}, false
	}
	user, ok := m.users[device.UserID]
	return user, ok
}

func (m *UserManager) GetPolicy(userID string) (UMPolicy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	policy, ok := m.policies[userID]
	return policy, ok
}

func (m *UserManager) GenerateBasicPolicy(userID string) (UMPolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return UMPolicy{}, fmt.Errorf("user not found")
	}
	policy := m.generateBasicPolicyLocked(userID)
	if existing, ok := m.policies[userID]; ok {
		policy.CreatedAt = existing.CreatedAt
	}
	m.policies[userID] = policy
	if err := m.saveLocked(); err != nil {
		return UMPolicy{}, err
	}
	return policy, nil
}

func (m *UserManager) IssueDeviceTicket(userID string, groupName string, ttl time.Duration) (UMDeviceTicket, error) {
	if userID == "" {
		return UMDeviceTicket{}, fmt.Errorf("user id is empty")
	}
	if groupName == "" {
		return UMDeviceTicket{}, fmt.Errorf("group name is empty")
	}
	if ttl <= 0 {
		return UMDeviceTicket{}, fmt.Errorf("invalid ttl")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return UMDeviceTicket{}, fmt.Errorf("user not found")
	}
	seq := m.enrollmentSeq.Add(1)
	ticket := UMDeviceTicket{
		Ticket:    fmt.Sprintf("dtk-%d-%d", time.Now().UnixNano(), seq),
		UserID:    userID,
		GroupName: groupName,
		ExpireAt:  time.Now().Add(ttl),
	}
	m.deviceTickets[ticket.Ticket] = ticket
	return ticket, nil
}

func (m *UserManager) AuthDevice(userID string, groupName string, deviceID string, ticket string) (UMAuthDevice, error) {
	if userID == "" || groupName == "" || deviceID == "" || ticket == "" {
		return UMAuthDevice{}, fmt.Errorf("user/group/device/ticket required")
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.deviceTickets[ticket]
	if !ok {
		return UMAuthDevice{}, fmt.Errorf("ticket not found")
	}
	if t.Used {
		return UMAuthDevice{}, fmt.Errorf("ticket already used")
	}
	if now.After(t.ExpireAt) {
		return UMAuthDevice{}, fmt.Errorf("ticket expired")
	}
	if t.UserID != userID || t.GroupName != groupName {
		return UMAuthDevice{}, fmt.Errorf("ticket mismatch")
	}
	if _, ok := m.users[userID]; !ok {
		return UMAuthDevice{}, fmt.Errorf("user not found")
	}
	record := UMAuthDevice{
		UserID:    userID,
		GroupName: groupName,
		DeviceID:  deviceID,
		AuthedAt:  now,
	}
	m.authedDevices[authedDeviceKey(groupName, deviceID)] = record
	t.Used = true
	m.deviceTickets[ticket] = t
	if err := m.saveLocked(); err != nil {
		return UMAuthDevice{}, err
	}
	return record, nil
}

func (m *UserManager) IsAuthedDevice(groupName string, deviceID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.authedDevices[authedDeviceKey(groupName, deviceID)]
	return ok
}

func (m *UserManager) RequireTicketAuthForGroup(groupName string) bool {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.deviceTickets {
		if t.GroupName == groupName && !t.Used && now.Before(t.ExpireAt) {
			return true
		}
	}
	return false
}

func toPubKeyHex(pubKey []byte, pubKeyAlg string) string {
	sum := sha256.Sum256(append([]byte(pubKeyAlg+":"), pubKey...))
	return hex.EncodeToString(sum[:])
}

func (m *UserManager) saveLocked() error {
	if m.store == nil {
		return nil
	}
	return m.store.Save(m.snapshotLocked())
}

func (m *UserManager) snapshotLocked() UMSnapshot {
	return UMSnapshot{
		UserSeq:          m.userSeq.Load(),
		EnrollmentSeq:    m.enrollmentSeq.Load(),
		Users:            cloneUsers(m.users),
		Policies:         clonePolicies(m.policies),
		Enrollments:      cloneEnrollments(m.enrollments),
		DeviceByPubKey:   cloneDevices(m.deviceByPubKey),
		CertifiedDevices: cloneAuthedDevices(m.authedDevices),
	}
}

func (m *UserManager) restore(snapshot UMSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.userSeq.Store(snapshot.UserSeq)
	m.enrollmentSeq.Store(snapshot.EnrollmentSeq)
	m.users = cloneUsers(snapshot.Users)
	m.policies = clonePolicies(snapshot.Policies)
	for userID := range m.users {
		if _, ok := m.policies[userID]; !ok {
			m.policies[userID] = m.generateBasicPolicyLocked(userID)
		}
	}
	m.enrollments = cloneEnrollments(snapshot.Enrollments)
	m.deviceByPubKey = cloneDevices(snapshot.DeviceByPubKey)
	m.authedDevices = cloneAuthedDevices(snapshot.CertifiedDevices)
}

func cloneUsers(src map[string]UMUser) map[string]UMUser {
	dst := make(map[string]UMUser, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneEnrollments(src map[string]UMEnrollment) map[string]UMEnrollment {
	dst := make(map[string]UMEnrollment, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneDevices(src map[string]UMDevice) map[string]UMDevice {
	dst := make(map[string]UMDevice, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func clonePolicies(src map[string]UMPolicy) map[string]UMPolicy {
	dst := make(map[string]UMPolicy, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneAuthedDevices(src map[string]UMAuthDevice) map[string]UMAuthDevice {
	dst := make(map[string]UMAuthDevice, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func authedDeviceKey(groupName string, deviceID string) string {
	return groupName + "|" + deviceID
}

func (m *UserManager) generateBasicPolicyLocked(userID string) UMPolicy {
	now := time.Now()
	return UMPolicy{
		UserID:                  userID,
		GroupName:               userID,
		UserExpireAtUnixMs:      0,
		UserGracePeriodSeconds:  int64((24 * time.Hour).Seconds()),
		AllowP2P:                true,
		AllowRelay:              true,
		MaxDevices:              32,
		EnrollmentTTLSeconds:    int64((15 * time.Minute).Seconds()),
		GatewayTicketTTLSeconds: int64((2 * time.Minute).Seconds()),
		CreatedAt:               now,
		UpdatedAt:               now,
	}
}
