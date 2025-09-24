package simpleobfs

import "github.com/tearsful/outbound/dialer"

func init() {
	dialer.FromLinkRegister("simpleobfs", NewSimpleObfs)
}
