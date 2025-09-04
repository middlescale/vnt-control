package handlers

import (
	"encoding/json"
	"net/http"
)

type Status struct {
	Service string `json:"service"`
	Status  string `json:"status"`
}

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Status{
		Service: "vnt-control",
		Status:  "ok",
	})
}
