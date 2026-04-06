package control

import (
	"fmt"
	"net"
	"strings"
	"time"

	"sdl-control/protocol"
	"sdl-control/protocol/pb"

	"google.golang.org/protobuf/proto"
)

const dnsProxyTimeout = 3 * time.Second

func (c *Controller) HandleDNSQueryPacket(request *protocol.Packet) (*protocol.Packet, error) {
	var query pb.DnsQueryRequest
	if err := proto.Unmarshal(request.Payload, &query); err != nil {
		return nil, fmt.Errorf("DnsQueryRequest unmarshal error: %w", err)
	}
	response := &pb.DnsQueryResponse{
		RequestId: query.GetRequestId(),
	}
	if len(query.GetQuery()) == 0 {
		response.Error = "dns query payload is empty"
		return c.buildServicePacket(request, protocol.AppProtoDNSQueryResponse, response)
	}
	reply, err := c.proxyDNSQuery(query.GetQuery())
	if err != nil {
		response.Error = err.Error()
	} else {
		response.Response = reply
	}
	return c.buildServicePacket(request, protocol.AppProtoDNSQueryResponse, response)
}

func (c *Controller) proxyDNSQuery(query []byte) ([]byte, error) {
	target := strings.TrimSpace(c.cfg.DNSServiceAddr)
	if target == "" {
		return nil, fmt.Errorf("dns_service_addr is empty")
	}
	conn, err := net.DialTimeout("udp", target, dnsProxyTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial dns_service_addr %s: %w", target, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(dnsProxyTimeout)); err != nil {
		return nil, fmt.Errorf("set dns proxy deadline: %w", err)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write dns query to %s: %w", target, err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read dns response from %s: %w", target, err)
	}
	return append([]byte(nil), buf[:n]...), nil
}
