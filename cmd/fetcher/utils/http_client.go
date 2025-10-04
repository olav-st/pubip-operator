package utils

import (
	"context"
	"net"
	"net/http"

	"go.fd.io/govpp/binapi/ip_types"
)

func GetClient(addressFamily ip_types.AddressFamily) http.Client {
	dialer := net.Dialer{}
	transport := http.DefaultTransport.(*http.Transport).Clone()

	var network string
	switch addressFamily {
	case ip_types.ADDRESS_IP6:
		network = "tcp6"
	default:
		network = "tcp4"
	}

	transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	return http.Client{Transport: transport}
}
