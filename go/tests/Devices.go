package tests

import (
	"github.com/saichler/probler/go/tests"
	"github.com/saichler/probler/go/types"
)

func Devices() *types.NetworkDeviceList {
	return tests.GenerateExactDeviceTableMockData()
}
