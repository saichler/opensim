package tests

import (
	"github.com/saichler/l8parser/go/parser/boot"
	"github.com/saichler/l8pollaris/go/types/l8tpollaris"
)

func Polling() []*l8tpollaris.L8Pollaris {
	return boot.GetAllPolarisModels()
}
