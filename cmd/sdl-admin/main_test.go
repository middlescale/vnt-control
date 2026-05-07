package main

import "testing"

func TestParseGatewayList(t *testing.T) {
	req := parseGateway([]string{"--list"})
	if req.Action != "gateway_list" {
		t.Fatalf("expected gateway_list action, got %q", req.Action)
	}
	if req.GatewayID != "" {
		t.Fatalf("expected empty gateway id for list, got %q", req.GatewayID)
	}
}

func TestParseGatewayEnlist(t *testing.T) {
	req := parseGateway([]string{"--enlist", "gw-1"})
	if req.Action != "gateway_enlist" {
		t.Fatalf("expected gateway_enlist action, got %q", req.Action)
	}
	if req.GatewayID != "gw-1" {
		t.Fatalf("expected gateway id gw-1, got %q", req.GatewayID)
	}
}

func TestParseGatewayDelist(t *testing.T) {
	req := parseGateway([]string{"--delist", "gw-1"})
	if req.Action != "gateway_delist" {
		t.Fatalf("expected gateway_delist action, got %q", req.Action)
	}
	if req.GatewayID != "gw-1" {
		t.Fatalf("expected gateway id gw-1, got %q", req.GatewayID)
	}
}
