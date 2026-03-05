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
	Action       string   `json:"action"`
	Name         string   `json:"name,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	GatewayID    string   `json:"gateway_id,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	UserID       string   `json:"user_id,omitempty"`
	Group        string   `json:"group,omitempty"`
	TTLSeconds   int64    `json:"ttl_seconds,omitempty"`
}

type adminResponse struct {
	OK           bool          `json:"ok"`
	UserID       string        `json:"user_id,omitempty"`
	Name         string        `json:"name,omitempty"`
	Domain       string        `json:"domain,omitempty"`
	Ticket       string        `json:"ticket,omitempty"`
	ExpireAtUnix int64         `json:"expire_at_unix,omitempty"`
	Gateways     []gatewayInfo `json:"gateways,omitempty"`
	Error        string        `json:"error,omitempty"`
}

type gatewayInfo struct {
	GatewayID          string   `json:"gateway_id"`
	Endpoint           string   `json:"endpoint"`
	Approved           bool     `json:"approved"`
	Default            bool     `json:"default"`
	Reported           bool     `json:"reported"`
	Alive              bool     `json:"alive"`
	Capabilities       []string `json:"capabilities,omitempty"`
	UpdatedAtUnix      int64    `json:"updated_at_unix,omitempty"`
}

func main() {
	createUser := flag.String("createUser", "", "create user by name")
	domain := flag.String("domain", "ms.net", "domain fqdn for user (default ms.net)")
	issueTicket := flag.Bool("issueDeviceTicket", false, "issue device ticket")
	listGateway := flag.Bool("listGateway", false, "list default and approved gateways")
	listGatewaySnake := flag.Bool("list_gateway", false, "list default and approved gateways")
	registerGateway := flag.Bool("registerGateway", false, "approve gateway by id")
	registerGatewaySnake := flag.Bool("register_gateway", false, "approve gateway")
	gatewayID := flag.String("gatewayId", "", "gateway id")
	gatewayIDSnake := flag.String("gateway_id", "", "gateway id")
	endpoint := flag.String("endpoint", "", "gateway endpoint host:port (deprecated for approval)")
	caps := flag.String("caps", "quic_stream_relay_v1", "comma-separated gateway capabilities")
	userID := flag.String("userId", "", "user id")
	group := flag.String("group", "", "group name")
	ttlSeconds := flag.Int64("ttlSeconds", 600, "ticket ttl seconds")
	socket := flag.String("socket", defaultSocketPath(), "admin unix socket path")
	flag.Parse()

	var req adminRequest
	switch {
	case strings.TrimSpace(*createUser) != "":
		req = adminRequest{Action: "create_user", Name: strings.TrimSpace(*createUser), Domain: strings.TrimSpace(*domain)}
	case *issueTicket:
		if strings.TrimSpace(*userID) == "" || strings.TrimSpace(*group) == "" {
			fatalUsage()
		}
		req = adminRequest{Action: "issue_device_ticket", UserID: strings.TrimSpace(*userID), Group: strings.TrimSpace(*group), TTLSeconds: *ttlSeconds}
	case *listGateway || *listGatewaySnake:
		req = adminRequest{Action: "list_gateway"}
	case *registerGateway || *registerGatewaySnake:
		gid := strings.TrimSpace(*gatewayID)
		if gid == "" {
			gid = strings.TrimSpace(*gatewayIDSnake)
		}
		if gid == "" {
			fatalUsage()
		}
		req = adminRequest{
			Action:       "register_gateway",
			GatewayID:    gid,
			Endpoint:     strings.TrimSpace(*endpoint),
			Capabilities: splitCSV(*caps),
		}
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
		fmt.Printf("created user: id=%s name=%s domain=%s\n", resp.UserID, resp.Name, resp.Domain)
	case "issue_device_ticket":
		fmt.Printf("issued ticket: %s expire_at_unix=%d\n", resp.Ticket, resp.ExpireAtUnix)
	case "register_gateway":
		fmt.Println("gateway registered")
	case "list_gateway":
		for _, gw := range resp.Gateways {
			fmt.Printf("gateway=%s endpoint=%s default=%t approved=%t reported=%t alive=%t updated_at_unix=%d\n", gw.GatewayID, gw.Endpoint, gw.Default, gw.Approved, gw.Reported, gw.Alive, gw.UpdatedAtUnix)
		}
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
	fmt.Fprintln(os.Stderr, "  vnt-admin --createUser user1 [--domain ms.net]")
	fmt.Fprintln(os.Stderr, "  vnt-admin --issueDeviceTicket --userId u-1 --group g1 [--ttlSeconds 600]")
	fmt.Fprintln(os.Stderr, "  vnt-admin --list_gateway")
	fmt.Fprintln(os.Stderr, "  vnt-admin --register_gateway --gateway_id gw-1")
	os.Exit(2)
}

func splitCSV(v string) []string {
	items := strings.Split(v, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		s := strings.TrimSpace(item)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func defaultSocketPath() string {
	if v := os.Getenv("VNT_ADMIN_SOCKET"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/tmp/vnt-control-admin.sock"
}
