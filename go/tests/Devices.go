package testside

import "github.com/saichler/probler/go/types"

func Devices() *types.NetworkDeviceList {
	return GenerateExactDeviceTableMockData()
}
