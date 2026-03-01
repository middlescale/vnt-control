package control

import "time"

func (c *Controller) UMCreateUser(name string) (UMUser, error) {
	return c.um.CreateUser(name)
}

func (c *Controller) UMCreateEnrollment(userID string, ttl time.Duration) (UMEnrollment, error) {
	return c.um.CreateEnrollment(userID, ttl)
}

func (c *Controller) UMBindDevice(code string, deviceID string, pubKey []byte, pubKeyAlg string) (UMDevice, error) {
	return c.um.BindDeviceByEnrollment(code, deviceID, pubKey, pubKeyAlg)
}

func (c *Controller) UMFindUserByDevicePubKey(pubKey []byte, pubKeyAlg string) (UMUser, bool) {
	return c.um.FindUserByDevicePubKey(pubKey, pubKeyAlg)
}

func (c *Controller) UMGetPolicy(userID string) (UMPolicy, bool) {
	return c.um.GetPolicy(userID)
}

func (c *Controller) UMGenerateBasicPolicy(userID string) (UMPolicy, error) {
	return c.um.GenerateBasicPolicy(userID)
}
