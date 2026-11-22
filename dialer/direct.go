package dialer

import (
	"github.com/tearsful/outbound/netproxy"
	"github.com/tearsful/outbound/protocol/direct"
)

func NewDirectDialer(option *ExtraOption, fullcone bool) (netproxy.Dialer, *Property) {
	property := &Property{
		Name:     "direct",
		Address:  "",
		Protocol: "",
		Link:     "",
	}
	if fullcone {
		return direct.FullconeDirect, property
	} else {
		return direct.SymmetricDirect, property
	}
}
