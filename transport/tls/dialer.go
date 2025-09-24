package tls

import "github.com/tearsful/outbound/dialer"

func init() {
	dialer.FromLinkRegister("tls", NewTls)
	dialer.FromLinkRegister("utls", NewTls)
}
