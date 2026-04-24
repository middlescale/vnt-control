package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteResponseListGatewayFormatsTable(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := writeResponse(&stdout, &stderr, "list_gateway", adminResponse{
		Gateways: []gatewayInfo{
			{
				GatewayID:     "gw-1",
				Endpoint:      "10.0.0.1:443",
				Default:       true,
				Approved:      true,
				Reported:      true,
				Alive:         true,
				Capabilities:  []string{"quic_stream_relay_v1", "icmp_v1"},
				UpdatedAtUnix: 1713926400,
			},
		},
	})
	if err != nil {
		t.Fatalf("writeResponse returned error: %v", err)
	}

	got := stdout.String()
	for _, want := range []string{
		"Gateways (1)",
		"ID",
		"APPROVED",
		"gw-1",
		"10.0.0.1:443",
		"yes",
		"quic_stream_relay_v1,icmp_v1",
		formatUnix(1713926400),
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("gateway output missing %q:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got: %s", stderr.String())
	}
}

func TestWriteResponseExtendDeviceExpiryFormatsSummaryAndTable(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := writeResponse(&stdout, &stderr, "extend_device_expiry", adminResponse{
		UpdatedCount: 1,
		Devices: []deviceInfo{
			{
				UserID:             "u-1",
				Group:              "sales.ms.net",
				Name:               "laptop-01",
				DeviceID:           "dev-1",
				VirtualIP:          "10.26.0.2",
				ControlOnline:      true,
				DataPlaneReachable: false,
				AuthExpireAtUnix:   1713926400,
				UpdatedAtUnix:      1713926500,
			},
		},
	})
	if err != nil {
		t.Fatalf("writeResponse returned error: %v", err)
	}

	got := stdout.String()
	for _, want := range []string{
		"Extended 1 device(s)",
		"USER ID",
		"laptop-01",
		"yes",
		"no",
		"valid",
		formatUnix(1713926500),
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("device output missing %q:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got: %s", stderr.String())
	}
}

func TestWriteJSONOutputsStructuredResponse(t *testing.T) {
	var stdout bytes.Buffer
	resp := adminResponse{
		OK:     true,
		UserID: "u-1",
		Name:   "alice",
		Domain: "sales.ms.net",
	}

	if err := writeJSON(&stdout, resp); err != nil {
		t.Fatalf("writeJSON returned error: %v", err)
	}

	var decoded adminResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid json: %v\n%s", err, stdout.String())
	}
	if !decoded.OK || decoded.UserID != "u-1" || decoded.Name != "alice" || decoded.Domain != "sales.ms.net" {
		t.Fatalf("unexpected decoded response: %+v", decoded)
	}
	if !strings.Contains(stdout.String(), "\"ok\": true") {
		t.Fatalf("expected pretty json output, got:\n%s", stdout.String())
	}
}
