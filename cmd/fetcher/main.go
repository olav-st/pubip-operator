package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"go.fd.io/govpp/binapi/ip_types"
	"olav.ninja/pubip-operator/cmd/fetcher/sources"
)

type params struct {
	addressFamily    string
	format           string
	requestedSources string
	strategy         string
	verbose          bool
}

var availableSources = map[string]sources.IpSource{
	"akami":       sources.NewAkamiCheckipIpSource(),
	"aws_checkip": sources.NewAwsCheckipIpSource(),
	"ipify":       sources.NewIpifyCheckipIpSource(),
	"ipinfo":      sources.NewIpinfoCheckipIpSource(),
}

func (p *params) validateParams() error {
	if p.requestedSources == "" {
		return fmt.Errorf("sources parameter is required")
	}

	if srcs := strings.Split(p.requestedSources, ","); slices.ContainsFunc(srcs, func(s string) bool {
		return strings.TrimSpace(s) == ""
	}) {
		return fmt.Errorf("sources list contains empty entries")
	}

	if !slices.Contains([]string{"plain", "json", "yaml"}, strings.ToLower(p.format)) {
		return fmt.Errorf("format must be one of: plain, json, yaml")
	}

	if !slices.Contains([]string{"ipv4", "ipv6"}, strings.ToLower(p.addressFamily)) {
		return fmt.Errorf("address-family must be either ipv4 or ipv6")
	}

	if !slices.Contains([]string{"first", "all"}, strings.ToLower(p.strategy)) {
		return fmt.Errorf("strategy must be either first or all")
	}

	return nil
}

func fetchWithFirstStrategy(srcs []string, addressFamily ip_types.AddressFamily, verbose bool) (net.IP, error) {
	var lastError error

	for _, source := range srcs {
		if verbose {
			fmt.Printf("Trying source: %s\n", source)
		}

		address, err := availableSources[source].GetPublicIp(addressFamily)
		if err != nil {
			if verbose {
				fmt.Printf("Source %s failed: %v\n", source, err)
			}
			lastError = err
			continue
		}

		if verbose {
			fmt.Printf("Source %s succeeded: %s\n", source, address)
		}
		return address, nil
	}

	return nil, fmt.Errorf("all sources failed, last error: %v", lastError)
}

func fetchWithAllStrategy(srcs []string, addressFamily ip_types.AddressFamily, verbose bool) (net.IP, error) {
	var addresses = make([]net.IP, 0, len(srcs))
	var sourceNames = make([]string, 0, len(srcs))

	for _, source := range srcs {
		if verbose {
			fmt.Printf("Trying source: %s\n", source)
		}

		address, err := availableSources[source].GetPublicIp(addressFamily)
		if err != nil {
			return nil, fmt.Errorf("source %s failed: %v", source, err)
		}

		if verbose {
			fmt.Printf("Source %s returned: %s\n", source, address)
		}

		addresses = append(addresses, address)
		sourceNames = append(sourceNames, source)
	}

	// Check if all addresses are the same
	if len(addresses) > 1 {
		firstAddress := addresses[0]
		for i, addr := range addresses[1:] {
			if !addr.Equal(firstAddress) {
				return nil, fmt.Errorf("sources returned different IP addresses: %s (%s) != %s (%s)",
					firstAddress, sourceNames[0], addr, sourceNames[i+1])
			}
		}
	}

	return addresses[0], nil
}

func main() {
	var p params

	flag.StringVar(&p.requestedSources, "sources", "",
		"Comma separated list of sources to fetch public IP from")
	flag.StringVar(&p.format, "format", "plain",
		"Output format. Can be plain, json or yaml")
	flag.StringVar(&p.addressFamily, "address-family", "ipv4",
		"IP address family to return. Can be either ipv4 or ipv6")
	flag.StringVar(&p.strategy, "strategy", "first",
		"Which sources should be used. Can be either first or all.\n"+
			"first: first source that returns an IP-address without error will be used. Fails if all sources return errors\n"+
			"all: all sources will be used. Fails if any of the sources return errors or if different IP-addresses are returned")
	flag.BoolVar(&p.verbose, "verbose", false,
		"Enable verbose logging")
	flag.Parse()

	if err := p.validateParams(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var addressFamily ip_types.AddressFamily
	switch p.addressFamily {
	case "ipv6":
		addressFamily = ip_types.ADDRESS_IP6
	default:
		addressFamily = ip_types.ADDRESS_IP4
	}

	if p.verbose {
		fmt.Printf("Sources: %s\n", p.requestedSources)
		fmt.Printf("Format: %s\n", p.format)
		fmt.Printf("Address Family: %s\n", p.addressFamily)
		fmt.Printf("Strategy: %s\n", p.strategy)
	}

	// Trim whitespace from source names
	requestedSources := strings.Split(p.requestedSources, ",")
	for i, source := range requestedSources {
		requestedSources[i] = strings.TrimSpace(source)
	}

	// Validate that all requested sources exist
	for _, source := range requestedSources {
		source = strings.TrimSpace(source)
		if _, ok := availableSources[source]; !ok {
			fmt.Fprintf(os.Stderr, "Error: unknown source %v\n", source)
			os.Exit(1)
		}
	}

	var address net.IP
	var err error

	// Execute strategy
	switch strings.ToLower(p.strategy) {
	case "first":
		address, err = fetchWithFirstStrategy(requestedSources, addressFamily, p.verbose)
	case "all":
		address, err = fetchWithAllStrategy(requestedSources, addressFamily, p.verbose)
	default:
		fmt.Fprintf(os.Stderr, "Error: invalid strategy %v\n", p.strategy)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Output the result based on format
	switch strings.ToLower(p.format) {
	case "plain":
		fmt.Printf("%s\n", address)
	case "json":
		fmt.Printf("{\"ip\": \"%s\"}\n", address)
	case "yaml":
		fmt.Printf("ip: %s\n", address)
	}
}
