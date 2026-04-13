package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type adminRequest struct {
	Action       string   `json:"action"`
	Name         string   `json:"name,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	GatewayID    string   `json:"gateway_id,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	Sections     []string `json:"sections,omitempty"`
	UserID       string   `json:"user_id,omitempty"`
	Group        string   `json:"group,omitempty"`
	DeviceID     string   `json:"device_id,omitempty"`
	All          bool     `json:"all,omitempty"`
	TTLSeconds   int64    `json:"ttl_seconds,omitempty"`
	TimeoutSec   int64    `json:"timeout_sec,omitempty"`
	DurationSec  int64    `json:"duration_sec,omitempty"`
}

type adminResponse struct {
	OK           bool            `json:"ok"`
	UserID       string          `json:"user_id,omitempty"`
	Name         string          `json:"name,omitempty"`
	Domain       string          `json:"domain,omitempty"`
	Ticket       string          `json:"ticket,omitempty"`
	ExpireAtUnix int64           `json:"expire_at_unix,omitempty"`
	Gateways     []gatewayInfo   `json:"gateways,omitempty"`
	Devices      []deviceInfo    `json:"devices,omitempty"`
	Domains      []string        `json:"domains,omitempty"`
	DNSSnapshot  any             `json:"dns_snapshot,omitempty"`
	DebugResult  json.RawMessage `json:"debug_result,omitempty"`
	DebugPath    string          `json:"debug_path,omitempty"`
	DebugWatchID uint64          `json:"debug_watch_id,omitempty"`
	UpdatedCount int             `json:"updated_count,omitempty"`
	Error        string          `json:"error,omitempty"`
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
	AuthedAtUnix       int64  `json:"authed_at_unix,omitempty"`
	AuthExpireAtUnix   int64  `json:"auth_expire_at_unix,omitempty"`
	AuthExpired        bool   `json:"auth_expired,omitempty"`
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
	case "extendDeviceExpiry", "extend_device_expiry":
		req = parseExtendDeviceExpiry(args[1:])
	case "registerGateway", "register_gateway":
		req = parseRegisterGateway(args[1:])
	case "dnsDomains", "dns_domains":
		req = parseDNSDomains(args[1:])
	case "dnsSnapshot", "dns_snapshot":
		req = parseDNSSnapshot(args[1:])
	case "collectDebug", "collect_debug":
		req = parseCollectDebug(args[1:])
	case "startDebugWatch", "start_debug_watch":
		req = parseStartDebugWatch(args[1:])
	case "stopDebugWatch", "stop_debug_watch":
		req = parseStopDebugWatch(args[1:])
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
		expireAt := time.Unix(resp.ExpireAtUnix, 0).Local().Format(time.RFC3339)
		fmt.Printf("issued ticket: %s expire_at_unix=%d expire_at=%s\n", resp.Ticket, resp.ExpireAtUnix, expireAt)
	case "register_gateway":
		fmt.Println("gateway registered")
	case "list_gateway":
		for _, gw := range resp.Gateways {
			fmt.Printf("gateway=%s endpoint=%s default=%t approved=%t reported=%t alive=%t updated_at_unix=%d\n", gw.GatewayID, gw.Endpoint, gw.Default, gw.Approved, gw.Reported, gw.Alive, gw.UpdatedAtUnix)
		}
	case "list_device":
		for _, device := range resp.Devices {
			authExpireAt := ""
			if device.AuthExpireAtUnix > 0 {
				authExpireAt = time.Unix(device.AuthExpireAtUnix, 0).Local().Format(time.RFC3339)
			}
			fmt.Printf("user_id=%s group=%s device_id=%s name=%s virtual_ip=%s control_online=%t data_plane_reachable=%t auth_expired=%t auth_expire_at_unix=%d auth_expire_at=%s updated_at_unix=%d\n", device.UserID, device.Group, device.DeviceID, device.Name, device.VirtualIP, device.ControlOnline, device.DataPlaneReachable, device.AuthExpired, device.AuthExpireAtUnix, authExpireAt, device.UpdatedAtUnix)
		}
	case "extend_device_expiry":
		fmt.Printf("extended %d device(s)\n", resp.UpdatedCount)
		for _, device := range resp.Devices {
			authExpireAt := ""
			if device.AuthExpireAtUnix > 0 {
				authExpireAt = time.Unix(device.AuthExpireAtUnix, 0).Local().Format(time.RFC3339)
			}
			fmt.Printf("user_id=%s group=%s device_id=%s name=%s virtual_ip=%s control_online=%t data_plane_reachable=%t auth_expired=%t auth_expire_at_unix=%d auth_expire_at=%s updated_at_unix=%d\n", device.UserID, device.Group, device.DeviceID, device.Name, device.VirtualIP, device.ControlOnline, device.DataPlaneReachable, device.AuthExpired, device.AuthExpireAtUnix, authExpireAt, device.UpdatedAtUnix)
		}
	case "dns_domains":
		for _, domain := range resp.Domains {
			fmt.Println(domain)
		}
	case "dns_snapshot":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(resp.DNSSnapshot); err != nil {
			fmt.Fprintf(os.Stderr, "encode dns snapshot failed: %v\n", err)
			os.Exit(1)
		}
	case "collect_debug":
		if strings.TrimSpace(resp.DebugPath) != "" {
			fmt.Fprintf(os.Stderr, "saved debug snapshot: %s\n", resp.DebugPath)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(resp.DebugResult); err != nil {
			fmt.Fprintf(os.Stderr, "encode debug result failed: %v\n", err)
			os.Exit(1)
		}
	case "start_debug_watch":
		fmt.Printf("started debug watch: id=%d path=%s\n", resp.DebugWatchID, resp.DebugPath)
	case "stop_debug_watch":
		fmt.Printf("stopped debug watch: id=%d path=%s\n", resp.DebugWatchID, resp.DebugPath)
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

func parseExtendDeviceExpiry(args []string) adminRequest {
	fs := flag.NewFlagSet("extendDeviceExpiry", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID string
	var group string
	var deviceID string
	var all bool
	var ttlSeconds int64
	fs.StringVar(&userID, "userId", "", "user id")
	fs.StringVar(&userID, "u", "", "user id")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&deviceID, "deviceId", "", "device id")
	fs.StringVar(&deviceID, "d", "", "device id")
	fs.BoolVar(&all, "all", false, "extend all devices under the user")
	fs.Int64Var(&ttlSeconds, "ttlSeconds", int64((30 * 24 * time.Hour).Seconds()), "seconds to extend")
	fs.Int64Var(&ttlSeconds, "t", int64((30 * 24 * time.Hour).Seconds()), "seconds to extend")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(userID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	if all == (strings.TrimSpace(deviceID) != "") {
		fatalUsage()
	}
	return adminRequest{
		Action:     "extend_device_expiry",
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		DeviceID:   strings.TrimSpace(deviceID),
		All:        all,
		TTLSeconds: ttlSeconds,
	}
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

func parseDNSSnapshot(args []string) adminRequest {
	fs := flag.NewFlagSet("dnsSnapshot", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var domain string
	var group string
	fs.StringVar(&domain, "domain", "", "dns domain")
	fs.StringVar(&domain, "d", "", "dns domain")
	fs.StringVar(&group, "group", "", "optional short group name")
	fs.StringVar(&group, "g", "", "optional short group name")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(domain) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action: "dns_snapshot",
		Domain: strings.TrimSpace(domain),
		Group:  strings.TrimSpace(group),
	}
}

func parseDNSDomains(args []string) adminRequest {
	fs := flag.NewFlagSet("dnsDomains", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{Action: "dns_domains"}
}

func parseCollectDebug(args []string) adminRequest {
	fs := flag.NewFlagSet("collectDebug", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var name string
	var userID string
	var group string
	var sections string
	var timeoutSec int64
	fs.StringVar(&name, "name", "", "device display name")
	fs.StringVar(&name, "n", "", "device display name")
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&sections, "sections", "", "comma-separated sections (runtime,gateway,peers,routes,nat,traffic)")
	fs.StringVar(&sections, "s", "", "comma-separated sections")
	fs.Int64Var(&timeoutSec, "timeoutSec", 10, "collection timeout seconds")
	fs.Int64Var(&timeoutSec, "t", 10, "collection timeout seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:     "collect_debug",
		Name:       strings.TrimSpace(name),
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		Sections:   splitCSV(sections),
		TimeoutSec: timeoutSec,
	}
}

func parseStartDebugWatch(args []string) adminRequest {
	fs := flag.NewFlagSet("startDebugWatch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var name, userID, group, sections string
	var timeoutSec, durationSec int64
	fs.StringVar(&name, "name", "", "device display name")
	fs.StringVar(&name, "n", "", "device display name")
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&sections, "sections", "", "comma-separated sections (all,gateway,icmp,punch,route,runtime)")
	fs.StringVar(&sections, "s", "", "comma-separated sections")
	fs.Int64Var(&timeoutSec, "timeoutSec", 10, "start timeout seconds")
	fs.Int64Var(&timeoutSec, "t", 10, "start timeout seconds")
	fs.Int64Var(&durationSec, "durationSec", 300, "watch duration seconds")
	fs.Int64Var(&durationSec, "d", 300, "watch duration seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:      "start_debug_watch",
		Name:        strings.TrimSpace(name),
		UserID:      strings.TrimSpace(userID),
		Group:       strings.TrimSpace(group),
		Sections:    splitCSV(sections),
		TimeoutSec:  timeoutSec,
		DurationSec: durationSec,
	}
}

func parseStopDebugWatch(args []string) adminRequest {
	fs := flag.NewFlagSet("stopDebugWatch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var name, userID, group string
	var timeoutSec int64
	fs.StringVar(&name, "name", "", "device display name")
	fs.StringVar(&name, "n", "", "device display name")
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.Int64Var(&timeoutSec, "timeoutSec", 10, "stop timeout seconds")
	fs.Int64Var(&timeoutSec, "t", 10, "stop timeout seconds")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:     "stop_debug_watch",
		Name:       strings.TrimSpace(name),
		UserID:     strings.TrimSpace(userID),
		Group:      strings.TrimSpace(group),
		TimeoutSec: timeoutSec,
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
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] extendDeviceExpiry --userId/-u u-1 (--deviceId/-d dev-1 | --all) [--group/-g sales.ms.net] [--ttlSeconds/-t 2592000]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] registerGateway --gateway-id/-g gw-1")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] dnsDomains")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] dnsSnapshot --domain/-d ms.net [--group/-g default]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] collectDebug --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--sections/-s runtime,gateway,peers,routes,nat,traffic] [--timeoutSec/-t 10]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] startDebugWatch --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--sections/-s all,gateway,icmp,punch,route,runtime] [--durationSec/-d 300] [--timeoutSec/-t 10]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] stopDebugWatch --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--timeoutSec/-t 10]")
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
