package control

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func normalizeRenameName(newName string) (string, error) {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return "", fmt.Errorf("name is empty")
	}
	if len(newName) > 128 {
		return "", fmt.Errorf("name too long")
	}
	return newName, nil
}

func pendingDeviceRenameKey(groupName, deviceID string) string {
	return strings.TrimSpace(groupName) + "\x00" + strings.TrimSpace(deviceID)
}

func (c *Controller) queuePendingDeviceRename(record PendingDeviceRename) {
	c.renameMu.Lock()
	defer c.renameMu.Unlock()
	record.RequestedAtUnix = time.Now().Unix()
	c.pendingDeviceRename[pendingDeviceRenameKey(record.Group, record.DeviceID)] = record
}

func (c *Controller) clearPendingDeviceRename(groupName, deviceID string) {
	c.renameMu.Lock()
	defer c.renameMu.Unlock()
	delete(c.pendingDeviceRename, pendingDeviceRenameKey(groupName, deviceID))
}

func (c *Controller) resolveAuthedRenameTarget(deviceID, userID, group string) (UMAuthDevice, error) {
	deviceID = strings.TrimSpace(deviceID)
	userID = strings.TrimSpace(userID)
	group = strings.TrimSpace(group)
	if deviceID == "" {
		return UMAuthDevice{}, fmt.Errorf("device_id required")
	}

	c.um.mu.RLock()
	defer c.um.mu.RUnlock()

	var matches []UMAuthDevice
	for _, record := range c.um.authedDevices {
		if record.DeviceID != deviceID {
			continue
		}
		if group != "" && !strings.EqualFold(record.GroupName, group) {
			continue
		}
		if userID != "" && !strings.EqualFold(record.UserID, userID) {
			continue
		}
		matches = append(matches, record)
	}
	if len(matches) == 0 {
		return UMAuthDevice{}, fmt.Errorf("device %q not found", deviceID)
	}
	if len(matches) > 1 {
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].GroupName != matches[j].GroupName {
				return matches[i].GroupName < matches[j].GroupName
			}
			return matches[i].UserID < matches[j].UserID
		})
		items := make([]string, 0, len(matches))
		for _, record := range matches {
			items = append(items, fmt.Sprintf("%s/%s/%s", record.UserID, record.GroupName, record.DeviceID))
		}
		return UMAuthDevice{}, fmt.Errorf("device %q matched multiple records: %s", deviceID, strings.Join(items, ", "))
	}
	return matches[0], nil
}

func (c *Controller) findPendingDeviceRename(deviceID, userID, group string) (PendingDeviceRename, error) {
	target, err := c.resolveAuthedRenameTarget(deviceID, userID, group)
	if err != nil {
		return PendingDeviceRename{}, err
	}
	c.renameMu.Lock()
	defer c.renameMu.Unlock()
	record, ok := c.pendingDeviceRename[pendingDeviceRenameKey(target.GroupName, target.DeviceID)]
	if !ok {
		return PendingDeviceRename{}, fmt.Errorf("no pending rename for device %q", target.DeviceID)
	}
	return record, nil
}

func (c *Controller) applyDeviceRename(groupName, deviceID, newName string) (uint32, error) {
	newName, err := normalizeRenameName(newName)
	if err != nil {
		return 0, err
	}
	if err := c.UMSetAuthedDeviceDisplayName(groupName, deviceID, newName); err != nil {
		return 0, err
	}
	var changedIP uint32
	c.nc.VirtualNetwork.mutex.Lock()
	defer c.nc.VirtualNetwork.mutex.Unlock()
	for _, network := range c.nc.VirtualNetwork.data {
		if !strings.EqualFold(network.Group, groupName) {
			continue
		}
		for ip, client := range network.Clients {
			if client.DeviceId != deviceID {
				continue
			}
			client.Name = newName
			network.UpsertClient(ip, client)
			network.Epoch++
			if changedIP == 0 {
				changedIP = ip
			}
		}
	}
	return changedIP, nil
}

func (c *Controller) ApprovePendingDeviceRename(deviceID, userID, group string) (string, uint32, error) {
	record, err := c.findPendingDeviceRename(deviceID, userID, group)
	if err != nil {
		return "", 0, err
	}
	changedIP, err := c.applyDeviceRename(record.Group, record.DeviceID, record.RequestedName)
	if err != nil {
		return "", 0, err
	}
	c.clearPendingDeviceRename(record.Group, record.DeviceID)
	return record.RequestedName, changedIP, nil
}

func (c *Controller) RenameDeviceByAdmin(deviceID, userID, group, newName string) (string, uint32, error) {
	target, err := c.resolveAuthedRenameTarget(deviceID, userID, group)
	if err != nil {
		return "", 0, err
	}
	newName, err = normalizeRenameName(newName)
	if err != nil {
		return "", 0, err
	}
	changedIP, err := c.applyDeviceRename(target.GroupName, target.DeviceID, newName)
	if err != nil {
		return "", 0, err
	}
	c.clearPendingDeviceRename(target.GroupName, target.DeviceID)
	return newName, changedIP, nil
}
