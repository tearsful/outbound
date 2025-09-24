package ws

import (
	"github.com/tearsful/outbound/dialer"
)

func init() {
	dialer.FromLinkRegister("ws", NewWs)
	dialer.FromLinkRegister("wss", NewWs)
}
