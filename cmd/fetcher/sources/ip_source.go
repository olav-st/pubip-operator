package sources

import (
	"net"

	"go.fd.io/govpp/binapi/ip_types"
)

type IpSource interface {
	GetPublicIp(addressFamily ip_types.AddressFamily) (net.IP, error)
}
