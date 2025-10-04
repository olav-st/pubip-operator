package sources

import (
	"io"
	"net"
	"strings"

	"go.fd.io/govpp/binapi/ip_types"
	"olav.ninja/pubip-operator/cmd/fetcher/utils"
)

type AkamiCheckipIpSource struct{}

func NewAkamiCheckipIpSource() *AkamiCheckipIpSource {
	return &AkamiCheckipIpSource{}
}

func (a *AkamiCheckipIpSource) GetPublicIp(addressFamily ip_types.AddressFamily) (net.IP, error) {
	client := utils.GetClient(addressFamily)

	resp, err := client.Get("https://whatismyip.akamai.com")
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
