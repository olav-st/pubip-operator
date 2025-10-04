package sources

import (
	"encoding/json"
	"io"
	"net"

	"go.fd.io/govpp/binapi/ip_types"
	"olav.ninja/pubip-operator/cmd/fetcher/utils"
)

type IpInfoResponse struct {
	Ip string `json:"ip"`
}

type IpinfoCheckipIpSource struct{}

func NewIpinfoCheckipIpSource() *IpinfoCheckipIpSource {
	return &IpinfoCheckipIpSource{}
}

func (a *IpinfoCheckipIpSource) GetPublicIp(addressFamily ip_types.AddressFamily) (net.IP, error) {
	client := utils.GetClient(addressFamily)

	resp, err := client.Get("https://ipinfo.io/json")
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

	var response IpInfoResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(response.Ip)
	if ip == nil {
		return nil, &net.ParseError{Type: "IP address", Text: response.Ip}
	}
	return ip, nil
}
