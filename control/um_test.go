package control

import (
	"testing"
	"time"
)

func TestUserManagementCreateBindLookup(t *testing.T) {
	um := NewUserManager()
	user, err := um.CreateUser("alice")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	enr, err := um.CreateEnrollment(user.UserID, time.Minute)
	if err != nil {
		t.Fatalf("CreateEnrollment failed: %v", err)
	}
	pub := []byte("device-pubkey-a")
	dev, err := um.BindDeviceByEnrollment(enr.Code, "device-a", pub, "ed25519")
	if err != nil {
		t.Fatalf("BindDeviceByEnrollment failed: %v", err)
	}
	if dev.UserID != user.UserID {
		t.Fatalf("unexpected user id: %s", dev.UserID)
	}
	lookup, ok := um.FindUserByDevicePubKey(pub, "ed25519")
	if !ok {
		t.Fatalf("FindUserByDevicePubKey not found")
	}
	if lookup.UserID != user.UserID {
		t.Fatalf("unexpected lookup user id: %s", lookup.UserID)
	}
}

func TestUserManagementEnrollmentSingleUse(t *testing.T) {
	um := NewUserManager()
	user, _ := um.CreateUser("bob")
	enr, _ := um.CreateEnrollment(user.UserID, time.Minute)
	_, err := um.BindDeviceByEnrollment(enr.Code, "device-b", []byte("pk-b"), "ed25519")
	if err != nil {
		t.Fatalf("first bind failed: %v", err)
	}
	_, err = um.BindDeviceByEnrollment(enr.Code, "device-c", []byte("pk-c"), "ed25519")
	if err == nil {
		t.Fatalf("expected second bind to fail for used enrollment")
	}
}

func TestUserManagementRejectCrossUserDeviceKeyReuse(t *testing.T) {
	um := NewUserManager()
	u1, _ := um.CreateUser("u1")
	u2, _ := um.CreateUser("u2")
	e1, _ := um.CreateEnrollment(u1.UserID, time.Minute)
	e2, _ := um.CreateEnrollment(u2.UserID, time.Minute)
	pub := []byte("same-device-key")
	if _, err := um.BindDeviceByEnrollment(e1.Code, "device-1", pub, "ed25519"); err != nil {
		t.Fatalf("bind user1 failed: %v", err)
	}
	if _, err := um.BindDeviceByEnrollment(e2.Code, "device-2", pub, "ed25519"); err == nil {
		t.Fatalf("expected cross-user key reuse to fail")
	}
}

func TestUserManagementBasicPolicyGeneratedOnCreateUser(t *testing.T) {
	um := NewUserManager()
	user, err := um.CreateUser("policy-user")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	policy, ok := um.GetPolicy(user.UserID)
	if !ok {
		t.Fatalf("expected default policy generated")
	}
	if !policy.AllowP2P || !policy.AllowRelay {
		t.Fatalf("unexpected default policy flags: %+v", policy)
	}
	if policy.MaxDevices <= 0 {
		t.Fatalf("unexpected max devices: %d", policy.MaxDevices)
	}
	if policy.GroupName == "" {
		t.Fatalf("expected group name")
	}
	if policy.UserExpireAtUnixMs != 0 {
		t.Fatalf("expected default non-expiring user")
	}
	if policy.UserGracePeriodSeconds <= 0 {
		t.Fatalf("expected positive grace period")
	}
}

func TestUserManagementRegenerateBasicPolicy(t *testing.T) {
	um := NewUserManager()
	user, err := um.CreateUser("policy-user-2")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	p1, ok := um.GetPolicy(user.UserID)
	if !ok {
		t.Fatalf("policy not found")
	}
	time.Sleep(time.Millisecond)
	p2, err := um.GenerateBasicPolicy(user.UserID)
	if err != nil {
		t.Fatalf("GenerateBasicPolicy failed: %v", err)
	}
	if p2.UpdatedAt.Before(p1.UpdatedAt) {
		t.Fatalf("expected updated_at move forward")
	}
}
