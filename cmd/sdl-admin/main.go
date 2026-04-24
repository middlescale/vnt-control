package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"text/tabwriter"
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
	jsonOutput := global.Bool("json", false, "print raw response as JSON")
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
	case "approveDeviceRename", "approve_device_rename":
		req = parseApproveDeviceRename(args[1:])
	case "renameDevice", "rename_device":
		req = parseRenameDevice(args[1:])
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
	if *jsonOutput {
		if err := writeJSON(os.Stdout, resp); err != nil {
			fmt.Fprintf(os.Stderr, "encode response failed: %v\n", err)
			os.Exit(1)
		}
		if !resp.OK {
			os.Exit(1)
		}
		return
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "admin error: %s\n", resp.Error)
		os.Exit(1)
	}
	if err := writeResponse(os.Stdout, os.Stderr, req.Action, resp); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func writeResponse(stdout, stderr io.Writer, action string, resp adminResponse) error {
	switch action {
	case "create_user":
		writeKeyValueBlock(stdout, "Created user", []kv{
			{Key: "User ID", Value: valueOrDash(resp.UserID)},
			{Key: "Name", Value: valueOrDash(resp.Name)},
			{Key: "Domain", Value: valueOrDash(resp.Domain)},
		})
	case "issue_device_ticket":
		writeKeyValueBlock(stdout, "Issued device ticket", []kv{
			{Key: "Ticket", Value: valueOrDash(resp.Ticket)},
			{Key: "Expires At", Value: formatUnix(resp.ExpireAtUnix)},
			{Key: "Expire Unix", Value: formatInt64(resp.ExpireAtUnix)},
		})
	case "register_gateway":
		writeKeyValueBlock(stdout, "Gateway registered", nil)
	case "list_gateway":
		writeGatewayTable(stdout, resp.Gateways)
	case "list_device":
		writeDeviceTable(stdout, "Devices", resp.Devices)
	case "extend_device_expiry":
		writeDeviceTable(stdout, fmt.Sprintf("Extended %d device(s)", resp.UpdatedCount), resp.Devices)
	case "approve_device_rename":
		writeKeyValueBlock(stdout, "Approved device rename", []kv{{Key: "Name", Value: valueOrDash(resp.Name)}})
	case "rename_device":
		writeKeyValueBlock(stdout, "Renamed device", []kv{{Key: "Name", Value: valueOrDash(resp.Name)}})
	case "dns_domains":
		writeDomains(stdout, resp.Domains)
	case "dns_snapshot":
		if err := writeJSON(stdout, resp.DNSSnapshot); err != nil {
			return fmt.Errorf("encode dns snapshot failed: %w", err)
		}
	case "collect_debug":
		if strings.TrimSpace(resp.DebugPath) != "" {
			writeKeyValueBlock(stderr, "Saved debug snapshot", []kv{{Key: "Path", Value: resp.DebugPath}})
		}
		if err := writeJSON(stdout, resp.DebugResult); err != nil {
			return fmt.Errorf("encode debug result failed: %w", err)
		}
	case "start_debug_watch":
		writeKeyValueBlock(stdout, "Started debug watch", []kv{
			{Key: "Watch ID", Value: formatUint64(resp.DebugWatchID)},
			{Key: "Path", Value: valueOrDash(resp.DebugPath)},
		})
	case "stop_debug_watch":
		writeKeyValueBlock(stdout, "Stopped debug watch", []kv{
			{Key: "Watch ID", Value: formatUint64(resp.DebugWatchID)},
			{Key: "Path", Value: valueOrDash(resp.DebugPath)},
		})
	}
	return nil
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

func parseApproveDeviceRename(args []string) adminRequest {
	fs := flag.NewFlagSet("approveDeviceRename", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID, group, deviceID string
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&deviceID, "deviceId", "", "device id")
	fs.StringVar(&deviceID, "d", "", "device id")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(deviceID) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:   "approve_device_rename",
		UserID:   strings.TrimSpace(userID),
		Group:    strings.TrimSpace(group),
		DeviceID: strings.TrimSpace(deviceID),
	}
}

func parseRenameDevice(args []string) adminRequest {
	fs := flag.NewFlagSet("renameDevice", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var userID, group, deviceID, name string
	fs.StringVar(&userID, "userId", "", "optional user id filter")
	fs.StringVar(&userID, "u", "", "optional user id filter")
	fs.StringVar(&group, "group", "", "optional group filter")
	fs.StringVar(&group, "g", "", "optional group filter")
	fs.StringVar(&deviceID, "deviceId", "", "device id")
	fs.StringVar(&deviceID, "d", "", "device id")
	fs.StringVar(&name, "name", "", "new device name")
	fs.StringVar(&name, "n", "", "new device name")
	if err := fs.Parse(args); err != nil {
		fatalUsage()
	}
	if strings.TrimSpace(deviceID) == "" || strings.TrimSpace(name) == "" || fs.NArg() != 0 {
		fatalUsage()
	}
	return adminRequest{
		Action:   "rename_device",
		UserID:   strings.TrimSpace(userID),
		Group:    strings.TrimSpace(group),
		DeviceID: strings.TrimSpace(deviceID),
		Name:     strings.TrimSpace(name),
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
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] createUser --userId/-u user1 [--group/-g sales.ms.net]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] issueDeviceTicket --userId/-u u-1 [--group/-g default.ms.net] [--ttlSeconds/-t 300]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] listGateway")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] listDevice --userId/-u u-1")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] extendDeviceExpiry --userId/-u u-1 (--deviceId/-d dev-1 | --all) [--group/-g sales.ms.net] [--ttlSeconds/-t 2592000]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] approveDeviceRename --deviceId/-d dev-1 [--group/-g sales.ms.net] [--userId/-u u-1]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] renameDevice --deviceId/-d dev-1 --name/-n new-name [--group/-g sales.ms.net] [--userId/-u u-1]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] registerGateway --gateway-id/-g gw-1")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] dnsDomains")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] dnsSnapshot --domain/-d ms.net [--group/-g default]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] collectDebug --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--sections/-s runtime,gateway,peers,routes,nat,traffic] [--timeoutSec/-t 10]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] startDebugWatch --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--sections/-s all,gateway,icmp,punch,route,runtime] [--durationSec/-d 300] [--timeoutSec/-t 10]")
	fmt.Fprintln(os.Stderr, "  sdl-admin [--socket /tmp/sdl-control-admin.sock] [--json] stopDebugWatch --name/-n win10-node [--group/-g default.ms.net] [--userId/-u u-1] [--timeoutSec/-t 10]")
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

type kv struct {
	Key   string
	Value string
}

func writeKeyValueBlock(w io.Writer, title string, pairs []kv) {
	fmt.Fprintln(w, title)
	for _, pair := range pairs {
		fmt.Fprintf(w, "  %-12s %s\n", pair.Key+":", pair.Value)
	}
}

func writeGatewayTable(w io.Writer, gateways []gatewayInfo) {
	fmt.Fprintf(w, "Gateways (%d)\n", len(gateways))
	if len(gateways) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	tw := newTabWriter(w)
	fmt.Fprintln(tw, "ID\tENDPOINT\tDEFAULT\tAPPROVED\tREPORTED\tALIVE\tCAPABILITIES\tUPDATED AT")
	for _, gw := range gateways {
		fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			valueOrDash(gw.GatewayID),
			valueOrDash(gw.Endpoint),
			formatBool(gw.Default),
			formatBool(gw.Approved),
			formatBool(gw.Reported),
			formatBool(gw.Alive),
			formatCSV(gw.Capabilities),
			formatUnix(gw.UpdatedAtUnix),
		)
	}
	_ = tw.Flush()
}

func writeDeviceTable(w io.Writer, title string, devices []deviceInfo) {
	fmt.Fprintf(w, "%s\n", title)
	if len(devices) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	tw := newTabWriter(w)
	fmt.Fprintln(tw, "USER ID\tGROUP\tNAME\tDEVICE ID\tVIRTUAL IP\tCONTROL\tDATA\tAUTH\tAUTH EXPIRES\tUPDATED AT")
	for _, device := range devices {
		fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			valueOrDash(device.UserID),
			valueOrDash(device.Group),
			valueOrDash(device.Name),
			valueOrDash(device.DeviceID),
			valueOrDash(device.VirtualIP),
			formatBool(device.ControlOnline),
			formatBool(device.DataPlaneReachable),
			formatAuthState(device),
			formatUnix(device.AuthExpireAtUnix),
			formatUnix(device.UpdatedAtUnix),
		)
	}
	_ = tw.Flush()
}

func writeDomains(w io.Writer, domains []string) {
	fmt.Fprintf(w, "DNS domains (%d)\n", len(domains))
	if len(domains) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	for _, domain := range domains {
		fmt.Fprintf(w, "  - %s\n", domain)
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newTabWriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

func formatBool(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func formatAuthState(device deviceInfo) string {
	if device.AuthExpired {
		return "expired"
	}
	if device.AuthExpireAtUnix > 0 {
		return "valid"
	}
	return "-"
}

func formatCSV(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}

func formatUnix(v int64) string {
	if v <= 0 {
		return "-"
	}
	return time.Unix(v, 0).Local().Format(time.RFC3339)
}

func formatInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", v)
}

func formatUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	return fmt.Sprintf("%d", v)
}

func valueOrDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}
