package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"vnt-control/control"

	log "github.com/sirupsen/logrus"
)

type adminRequest struct {
	Action string `json:"action"`
	Name   string `json:"name,omitempty"`
}

type adminResponse struct {
	OK     bool   `json:"ok"`
	UserID string `json:"user_id,omitempty"`
	Name   string `json:"name,omitempty"`
	Error  string `json:"error,omitempty"`
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
	default:
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "unsupported action"})
	}
}
