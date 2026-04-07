package control

import (
	"slices"
	"testing"

	"sdl-control/config"
)

func TestListDNSDomainsSorted(t *testing.T) {
	ctrl := &Controller{
		cfg: &config.Config{
			Domains: map[string]config.DomainConfig{
				"sales.ms.net": {},
				"ms.net":       {},
			},
		},
	}
	got := ctrl.ListDNSDomains()
	want := []string{"ms.net", "sales.ms.net"}
	if !slices.Equal(got, want) {
		t.Fatalf("unexpected domains: got %v want %v", got, want)
	}
}
