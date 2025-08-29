package tests

import (
	"github.com/saichler/l8parser/go/parser/boot"
	"github.com/saichler/l8pollaris/go/types"
)

func Polling() []*types.Pollaris {
	return boot.GetAllPolarisModels()
}
