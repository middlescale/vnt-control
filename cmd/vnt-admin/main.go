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

func main() {
	createUser := flag.String("createUser", "", "create user by name")
	issueTicket := flag.Bool("issueDeviceTicket", false, "issue device ticket")
	userID := flag.String("userId", "", "user id")
	group := flag.String("group", "", "group name")
	ttlSeconds := flag.Int64("ttlSeconds", 600, "ticket ttl seconds")
	socket := flag.String("socket", defaultSocketPath(), "admin unix socket path")
	flag.Parse()

	var req adminRequest
	switch {
	case strings.TrimSpace(*createUser) != "":
		req = adminRequest{Action: "create_user", Name: strings.TrimSpace(*createUser)}
	case *issueTicket:
		if strings.TrimSpace(*userID) == "" || strings.TrimSpace(*group) == "" {
			fatalUsage()
		}
		req = adminRequest{Action: "issue_device_ticket", UserID: strings.TrimSpace(*userID), Group: strings.TrimSpace(*group), TTLSeconds: *ttlSeconds}
	default:
		fatalUsage()
	}

	resp := call(*socket, req)
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "admin error: %s\n", resp.Error)
		os.Exit(1)
	}
	switch req.Action {
	case "create_user":
		fmt.Printf("created user: id=%s name=%s\n", resp.UserID, resp.Name)
	case "issue_device_ticket":
		fmt.Printf("issued ticket: %s expire_at_unix=%d\n", resp.Ticket, resp.ExpireAtUnix)
	}
}

func call(socket string, req adminRequest) adminResponse {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect admin socket failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
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
	return resp
}

func fatalUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  vnt-admin --createUser user1")
	fmt.Fprintln(os.Stderr, "  vnt-admin --issueDeviceTicket --userId u-1 --group g1 [--ttlSeconds 600]")
	os.Exit(2)
}

func defaultSocketPath() string {
	if v := os.Getenv("VNT_ADMIN_SOCKET"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/tmp/vnt-control-admin.sock"
}
