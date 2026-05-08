package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sdl-control/control"
	"sdl-control/util"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
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
	OK             bool                       `json:"ok"`
	UserID         string                     `json:"user_id,omitempty"`
	Name           string                     `json:"name,omitempty"`
	Domain         string                     `json:"domain,omitempty"`
	Domains        []string                   `json:"domains,omitempty"`
	Ticket         string                     `json:"ticket,omitempty"`
	ExpireAtUnix   int64                      `json:"expire_at_unix,omitempty"`
	Gateways       []control.GatewayAdminView `json:"gateways,omitempty"`
	Devices        []control.DeviceAdminView  `json:"devices,omitempty"`
	UpdatedDevices []control.DeviceAdminView  `json:"updated_devices,omitempty"`
	DNSSnapshot    *control.DNSSnapshotView   `json:"dns_snapshot,omitempty"`
	DebugResult    json.RawMessage            `json:"debug_result,omitempty"`
	DebugPath      string                     `json:"debug_path,omitempty"`
	DebugWatchID   uint64                     `json:"debug_watch_id,omitempty"`
	UpdatedCount   int                        `json:"updated_count,omitempty"`
	Error          string                     `json:"error,omitempty"`
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
		user, err := ctrl.UMCreateUserWithID(strings.TrimSpace(req.UserID), strings.TrimSpace(req.Group), strings.TrimSpace(req.Domain))
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, UserID: user.UserID, Name: user.Name, Domain: user.Domain})
	case "issue_device_ticket":
		group := strings.TrimSpace(req.Group)
		if group == "" {
			group = "default.ms.net"
		}
		ttl := req.TTLSeconds
		if ttl <= 0 {
			ttl = 300
		}
		t, err := ctrl.UMIssueDeviceTicket(strings.TrimSpace(req.UserID), group, time.Duration(ttl)*time.Second)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, Ticket: t.Ticket, ExpireAtUnix: t.ExpireAt.Unix()})
	case "register_gateway", "gateway_enlist":
		gatewayID := strings.TrimSpace(req.GatewayID)
		if gatewayID == "" {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "gateway_id required"})
			return
		}
		if err := ctrl.ApproveGatewayNodeByID(gatewayID); err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded(); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToIP(util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true})
	case "delist_gateway", "gateway_delist":
		gatewayID := strings.TrimSpace(req.GatewayID)
		if gatewayID == "" {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "gateway_id required"})
			return
		}
		if err := ctrl.DelistGatewayNodeByID(gatewayID); err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForGatewayChangeIfNeeded(); pushErr != nil {
			log.Errorf("BuildPushDeviceListPacketsForGatewayChangeIfNeeded error: %v", pushErr)
		} else {
			for _, push := range pushPackets {
				if push == nil || push.DstIP == nil {
					continue
				}
				if err := quicStreams.writeToIP(util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
					log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
				}
			}
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true})
	case "list_gateway", "gateway_list":
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, Gateways: ctrl.ListGateways()})
	case "list_device":
		userID := strings.TrimSpace(req.UserID)
		if userID == "" {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "user_id required"})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, Devices: ctrl.ListDevices(userID)})
	case "extend_device_expiry":
		userID := strings.TrimSpace(req.UserID)
		if userID == "" {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "user_id required"})
			return
		}
		ttl := req.TTLSeconds
		if ttl <= 0 {
			ttl = int64((30 * 24 * time.Hour).Seconds())
		}
		updated, err := ctrl.UMExtendAuthedDeviceExpiry(
			userID,
			strings.TrimSpace(req.Group),
			strings.TrimSpace(req.DeviceID),
			time.Duration(ttl)*time.Second,
			req.All,
		)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		devices := ctrl.ListDevices(userID)
		_ = json.NewEncoder(conn).Encode(adminResponse{
			OK:             true,
			Devices:        devices,
			UpdatedDevices: selectUpdatedDeviceViews(updated, devices),
			UpdatedCount:   len(updated),
		})
	case "approve_device_rename":
		appliedName, changedIP, err := ctrl.ApprovePendingDeviceRename(
			strings.TrimSpace(req.DeviceID),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
		)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		if changedIP != 0 {
			if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForPeerChange(changedIP); pushErr != nil {
				log.Errorf("BuildPushDeviceListPacketsForPeerChange error: %v", pushErr)
			} else {
				for _, push := range pushPackets {
					if push == nil || push.DstIP == nil {
						continue
					}
					if err := quicStreams.writeToIP(util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
						log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
					}
				}
			}
			if notifyPacket, notifyErr := ctrl.BuildDeviceRenameNotifyPacket(changedIP, 0, appliedName); notifyErr != nil {
				log.Errorf("BuildDeviceRenameNotifyPacket error: %v", notifyErr)
			} else if notifyPacket != nil {
				if err := quicStreams.writeToIP(changedIP, notifyPacket.Marshal()); err != nil {
					log.Warnf("DeviceRenameResponse dispatch failed: %s err=%v", util.Uint32ToIP(changedIP), err)
				}
			}
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, Name: appliedName})
	case "rename_device":
		appliedName, changedIP, err := ctrl.RenameDeviceByAdmin(
			strings.TrimSpace(req.DeviceID),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
			strings.TrimSpace(req.Name),
		)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		if changedIP != 0 {
			if pushPackets, pushErr := ctrl.BuildPushDeviceListPacketsForPeerChange(changedIP); pushErr != nil {
				log.Errorf("BuildPushDeviceListPacketsForPeerChange error: %v", pushErr)
			} else {
				for _, push := range pushPackets {
					if push == nil || push.DstIP == nil {
						continue
					}
					if err := quicStreams.writeToIP(util.IpToUint32(push.DstIP), push.Marshal()); err != nil {
						log.Warnf("PushDeviceList dispatch failed: %s err=%v", push.DstIP, err)
					}
				}
			}
			if notifyPacket, notifyErr := ctrl.BuildDeviceRenameNotifyPacket(changedIP, 0, appliedName); notifyErr != nil {
				log.Errorf("BuildDeviceRenameNotifyPacket error: %v", notifyErr)
			} else if notifyPacket != nil {
				if err := quicStreams.writeToIP(changedIP, notifyPacket.Marshal()); err != nil {
					log.Warnf("DeviceRenameResponse dispatch failed: %s err=%v", util.Uint32ToIP(changedIP), err)
				}
			}
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, Name: appliedName})
	case "dns_snapshot":
		snapshot, err := ctrl.BuildDNSSnapshot(strings.TrimSpace(req.Domain), strings.TrimSpace(req.Group))
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, DNSSnapshot: snapshot})
	case "dns_domains":
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, Domains: ctrl.ListDNSDomains()})
	case "collect_debug":
		timeout := req.TimeoutSec
		if timeout <= 0 {
			timeout = 10
		}
		packet, targetIP, requestID, err := ctrl.PrepareDebugCollectByName(
			strings.TrimSpace(req.Name),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
			req.Sections,
		)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		if err := quicStreams.writeToIP(targetIP, packet.Marshal()); err != nil {
			ctrl.CancelDebugWatchStart(requestID)
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		result, err := ctrl.AwaitDebugCollect(requestID, time.Duration(timeout)*time.Second)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		raw := json.RawMessage(result.SnapshotJSON)
		if !json.Valid(raw) {
			raw = json.RawMessage([]byte(fmt.Sprintf("{\"raw\":%q}", result.SnapshotJSON)))
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: true, DebugResult: raw, DebugPath: result.SavedPath})
	case "start_debug_watch":
		timeout := req.TimeoutSec
		if timeout <= 0 {
			timeout = 10
		}
		duration := req.DurationSec
		if duration <= 0 {
			duration = 300
		}
		packet, targetIP, requestID, err := ctrl.PrepareDebugWatchStartByName(
			strings.TrimSpace(req.Name),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
			req.Sections,
			time.Duration(duration)*time.Second,
		)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		if err := quicStreams.writeToIP(targetIP, packet.Marshal()); err != nil {
			ctrl.CancelDebugCollect(requestID)
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		result, err := ctrl.AwaitDebugWatchStart(requestID, time.Duration(timeout)*time.Second)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{
			OK:           true,
			DebugPath:    result.SavedPath,
			DebugWatchID: result.WatchID,
		})
	case "stop_debug_watch":
		timeout := req.TimeoutSec
		if timeout <= 0 {
			timeout = 10
		}
		packet, targetIP, requestID, err := ctrl.PrepareDebugWatchStopByName(
			strings.TrimSpace(req.Name),
			strings.TrimSpace(req.UserID),
			strings.TrimSpace(req.Group),
		)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		if err := quicStreams.writeToIP(targetIP, packet.Marshal()); err != nil {
			ctrl.CancelDebugWatchStop(requestID)
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		result, err := ctrl.AwaitDebugWatchStop(requestID, time.Duration(timeout)*time.Second)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(adminResponse{
			OK:           true,
			DebugPath:    result.SavedPath,
			DebugWatchID: result.WatchID,
		})
	default:
		_ = json.NewEncoder(conn).Encode(adminResponse{OK: false, Error: "unsupported action"})
	}
}

func selectUpdatedDeviceViews(updated []control.UMAuthDevice, devices []control.DeviceAdminView) []control.DeviceAdminView {
	if len(updated) == 0 {
		return nil
	}
	deviceByKey := make(map[string]control.DeviceAdminView, len(devices))
	for _, device := range devices {
		deviceByKey[device.Group+"\x00"+device.DeviceID] = device
	}
	updatedViews := make([]control.DeviceAdminView, 0, len(updated))
	for _, record := range updated {
		key := record.GroupName + "\x00" + record.DeviceID
		if device, ok := deviceByKey[key]; ok {
			updatedViews = append(updatedViews, device)
			continue
		}
		name := strings.TrimSpace(record.DisplayName)
		if name == "" {
			name = record.DeviceID
		}
		updatedViews = append(updatedViews, control.DeviceAdminView{
			UserID:           record.UserID,
			Group:            record.GroupName,
			Name:             name,
			DeviceID:         record.DeviceID,
			AuthedAtUnix:     record.AuthedAt.Unix(),
			AuthExpireAtUnix: record.AuthExpireAt.Unix(),
			AuthExpired:      !record.AuthExpireAt.IsZero() && time.Now().After(record.AuthExpireAt),
			UpdatedAtUnix:    record.AuthedAt.Unix(),
		})
	}
	return updatedViews
}
