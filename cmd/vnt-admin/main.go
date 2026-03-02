package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
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

func main() {
	createUser := flag.String("createUser", "", "create user by name")
	socket := flag.String("socket", defaultSocketPath(), "admin unix socket path")
	flag.Parse()
	if strings.TrimSpace(*createUser) == "" {
		fmt.Fprintln(os.Stderr, "usage: vnt-admin --createUser user1 [--socket /tmp/vnt-control-admin.sock]")
		os.Exit(2)
	}
	conn, err := net.Dial("unix", *socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect admin socket failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	req := adminRequest{Action: "create_user", Name: strings.TrimSpace(*createUser)}
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "send request failed: %v\n", err)
		os.Exit(1)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "read response failed: %v\n", err)
		os.Exit(1)
	}
	var resp adminResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "invalid response: %v\n", err)
		os.Exit(1)
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "admin error: %s\n", resp.Error)
		os.Exit(1)
	}
	fmt.Printf("created user: id=%s name=%s\n", resp.UserID, resp.Name)
}

func defaultSocketPath() string {
	if v := os.Getenv("VNT_ADMIN_SOCKET"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/tmp/vnt-control-admin.sock"
}
