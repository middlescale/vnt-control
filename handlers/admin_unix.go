package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"time"
	"vnt-control/control"

	log "github.com/sirupsen/logrus"
)

type adminRequest struct {
	Action     string `json:"action"`
	Name       string `json:"name,omitempty"`
	UserID     string `json:"user_id,omitempty"`
	Group      string `json:"group,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

type adminResponse struct {
	OK           bool   `json:"ok"`
	UserID       string `json:"user_id,omitempty"`
	Name         string `json:"name,omitempty"`
	Ticket       string `json:"ticket,omitempty"`
	ExpireAtUnix int64  `json:"expire_at_unix,omitempty"`
	Error        string `json:"error,omitempty"`
}

func StartAdminUnixServer(ctx context.Context, ctrl *control.Controller, socketPath string) error {
	if strings.TrimSpace(socketPath) == "" {
		return nil
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return err
	}
	log.Infof("admin unix socket listening on %s", socketPath)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleAdminConn(ctrl, conn)
		}
	}()
	return nil
}

func handleAdminConn(ctrl *control.Controller, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) == 0 {
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "invalid request"})
		return
	}
	var req adminRequest
	if err := json.Unmarshal(line, &req); err != nil {
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "invalid json"})
		return
	}
	switch req.Action {
	case "create_user":
		user, err := ctrl.UMCreateUser(strings.TrimSpace(req.Name))
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, UserID: user.UserID, Name: user.Name})
	case "issue_device_ticket":
		ttl := req.TTLSeconds
		if ttl <= 0 {
			ttl = 600
		}
		t, err := ctrl.UMIssueDeviceTicket(strings.TrimSpace(req.UserID), strings.TrimSpace(req.Group), time.Duration(ttl)*time.Second)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, Ticket: t.Ticket, ExpireAtUnix: t.ExpireAt.Unix()})
	default:
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "unsupported action"})
	}
}
