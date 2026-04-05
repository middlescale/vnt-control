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
	Devices      []deviceInfo  `json:"devices,omitempty"`
	Error        string        `json:"error,omitempty"`
}

type gatewayInfo struct {
	GatewayID     string   `json:"gateway_id"`
	Endpoint      string   `json:"endpoint"`
	Approved      bool     `json:"approved"`
	Default       bool     `json:"default"`
	Reported      bool     `json:"reported"`
	Alive         bool     `json:"alive"`
	Capabilities  []string `json:"capabilities,omitempty"`
	UpdatedAtUnix int64    `json:"updated_at_unix,omitempty"`
}

type deviceInfo struct {
	UserID             string `json:"user_id"`
	Group              string `json:"group"`
	Name               string `json:"name"`
	DeviceID           string `json:"device_id"`
	VirtualIP          string `json:"virtual_ip"`
	ControlOnline      bool   `json:"control_online"`
	DataPlaneReachable bool   `json:"data_plane_reachable"`
	UpdatedAtUnix      int64  `json:"updated_at_unix,omitempty"`
}

func main() {
	global := flag.NewFlagSet("sdl-admin", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	socket := global.String("socket", defaultSocketPath(), "admin unix socket path")
	if err := global.Parse(os.Args[1:]); err != nil {
		fatalUsage()
	}
	args := global.Args()
	if len(args) == 0 {
		fatalUsage()
	}

	var req adminRequest
	switch args[0] {
	case "createUser", "create_user":
		req = parseCreateUser(args[1:])
	case "issueDeviceTicket", "issue_device_ticket":
		req = parseIssueDeviceTicket(args[1:])
	case "listGateway", "list_gateway":
		req = parseListGateway(args[1:])
	case "listDevice", "list_device":
		req = parseListDevice(args[1:])
	case "registerGateway", "register_gateway":
		req = parseRegisterGateway(args[1:])
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
	case "list_device":
		for _, device := range resp.Devices {
			fmt.Printf("user_id=%s group=%s device_id=%s name=%s virtual_ip=%s control_online=%t data_plane_reachable=%t updated_at_unix=%d\n", device.UserID, device.Group, device.DeviceID, device.Name, device.VirtualIP, device.ControlOnline, device.DataPlaneReachable, device.UpdatedAtUnix)
		}
	}
}

func parseCreateUser(args []string) adminRequest {
	fs := flag.NewFlagSet("createUser", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID string
	var group string
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	fs.StringVar(&group, "group", "default", "default group name")
	fs.StringVar(&group, "g", "default", "default group name")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(userID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action: "create_user",
		UserID: strings.TrimSpace(userID),
		Group:  strings.TrimSpace(group),
	}
}

func parseIssueDeviceTicket(args []string) adminRequest {
	fs := flag.NewFlagSet("issueDeviceTicket", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID string
	var group string
	var ttlSeconds int64
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	fs.StringVar(&group, "group", "default.ms.net", "group name")
	fs.StringVar(&group, "g", "default.ms.net", "group name")
	fs.Int64Var(&ttlSeconds, "ttlSeconds", 300, "ticket ttl seconds")
	fs.Int64Var(&ttlSeconds, "t", 300, "ticket ttl seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(userID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:     "issue_device_ticket",
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		TTLSeconds: ttlSeconds,
	}
}

func parseListGateway(args []string) adminRequest {
	fs := flag.NewFlagSet("listGateway", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{Action: "list_gateway"}
}

func parseListDevice(args []string) adminRequest {
	fs := flag.NewFlagSet("listDevice", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID string
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(userID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{Action: "list_device", UserID: strings.TrimSpace(userID)}
}

func parseRegisterGateway(args []string) adminRequest {
	fs := flag.NewFlagSet("registerGateway", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var gatewayID string
	var endpoint string
	var caps string
	fs.StringVar(&gatewayID, "gatewayId", "", "gateway id")
	fs.StringVar(&gatewayID, "gateway_id", "", "gateway id")
	fs.StringVar(&gatewayID, "gateway-id", "", "gateway id")
	fs.StringVar(&gatewayID, "g", "", "gateway id")
	fs.StringVar(&endpoint, "endpoint", "", "gateway endpoint host:port (deprecated for approval)")
	fs.StringVar(&caps, "caps", "quic_stream_relay_v1", "comma-separated gateway capabilities")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(gatewayID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:       "register_gateway",
		GatewayID:    strings.TrimSpace(gatewayID),
		Endpoint:     strings.TrimSpace(endpoint),
		Capabilities: splitCSV(caps),
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
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] createUser --userId/-u user1 [--group/-g sales.ms.net]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] issueDeviceTicket --userId/-u u-1 [--group/-g default.ms.net] [--ttlSeconds/-t 300]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] listGateway")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] listDevice --userId/-u u-1")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] registerGateway --gateway-id/-g gw-1")
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
	if v := os.Getenv("SDL_ADMIN_SOCKET"); strings.TrimSpace(v) != "" {
		return v
	}
	return "/tmp/sdl-control-admin.sock"
}
