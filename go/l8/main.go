package main

import (
	"github.com/saichler/l8bus/go/overlay/vnet"
	"github.com/saichler/l8bus/go/overlay/vnic"
	"github.com/saichler/l8business/go/types/l8business"
	"github.com/saichler/l8reflect/go/reflect/helping"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8api"
	"github.com/saichler/l8types/go/types/l8health"
	"github.com/saichler/l8types/go/types/l8web"
	"github.com/saichler/l8utils/go/utils/ipsegment"
	"github.com/saichler/l8utils/go/utils/shared"
	"github.com/saichler/l8web/go/web/server"
	"github.com/saichler/opensim/go/proxy"
)

func main() {
	resources := shared.ResourcesOf("opensim", 50505, 0, false)
	resources.Logger().SetLogLevel(ifs.Info_Level)
	net := vnet.NewVNet(resources)
	net.Start()
	resources.Logger().Info("vnet started!")
	StartWebServer(23443, "/data/probler")
}

func StartWebServer(port int, cert string) {
	serverConfig := &server.RestServerConfig{
		Host:           ipsegment.MachineIP,
		Port:           port,
		Authentication: true,
		CertName:       cert,
		Prefix:         "/opensim/",
	}
	svr, err := server.NewRestServerNoIndex(serverConfig)
	if err != nil {
		panic(err)
	}

	nic := CreateVnic(50505, "opensimweb")

	//Activate the webpoints bservice
	sla := ifs.NewServiceLevelAgreement(&server.WebService{}, ifs.WebService, 0, false, nil)
	p, e := proxy.NewWebProxy("127.0.0.1:8080")
	if e != nil {
		panic(e)
	}
	sla.SetArgs(svr, p)
	nic.Resources().Services().Activate(sla, nic)

	nic.Resources().Logger().Info("Web Server Started!")

	svr.Start()
}

func CreateVnic(vnet uint32, name string) ifs.IVNic {
	resources := shared.ResourcesOf(name, vnet, 0, false)

	node, _ := resources.Introspector().Inspect(&l8business.L8Business{})
	helping.AddPrimaryKeyDecorator(node, "TaxId")

	nic := vnic.NewVirtualNetworkInterface(resources, nil)
	nic.Resources().SysConfig().KeepAliveIntervalSeconds = 60
	nic.Start()
	nic.WaitForConnection()

	nic.Resources().Registry().Register(&l8api.L8Query{})
	nic.Resources().Registry().Register(&l8web.L8Empty{})
	nic.Resources().Registry().Register(&l8health.L8Health{})
	nic.Resources().Registry().Register(&l8health.L8HealthList{})

	return nic
}
