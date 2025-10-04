package sources

import (
	"io"
	"net"
	"net/http"
	"strings"

	"go.fd.io/govpp/binapi/ip_types"
)

type IpifyCheckipIpSource struct{}

func NewIpifyCheckipIpSource() *IpifyCheckipIpSource {
	return &IpifyCheckipIpSource{}
}

func (a *IpifyCheckipIpSource) GetPublicIp(addressFamily ip_types.AddressFamily) (net.IP, error) {
	var url string
	switch addressFamily {
	case ip_types.ADDRESS_IP6:
		url = "https://api64.ipify.org?format=plain"
	default:
		url = "https://api.ipify.org?format=plain"
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, &net.ParseError{Type: "IP address", Text: ipStr}
	}
	return ip, nil
}
