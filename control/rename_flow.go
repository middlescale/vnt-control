package control

import (
	"fmt"
	"strings"
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
