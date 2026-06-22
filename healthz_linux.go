// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

func checkNetworkInterface(ifaceName string, ifaceIndex int) HealthCheckResult {
	if ifaceName == "" {
		return HealthCheckResult{OK: false, Error: "external interface not set"}
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("interface %q not found: %v", ifaceName, err)}
	}

	attrs := link.Attrs()
	if attrs.Flags&net.FlagUp == 0 {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("interface %q is not UP", ifaceName)}
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("failed to list addresses for %q: %v", ifaceName, err)}
	}
	if len(addrs) == 0 {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("interface %q has no IP addresses", ifaceName)}
	}

	return HealthCheckResult{OK: true, Message: fmt.Sprintf("interface %q is UP (index %d, MTU %d, %d addrs)", ifaceName, attrs.Index, attrs.MTU, len(addrs))}
}

func checkRoutingTable(network, ipv6Network string, ifaceIndex int) HealthCheckResult {
	var errors []string
	checked := 0

	if network != "" {
		checked++
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			errors = append(errors, fmt.Sprintf("invalid IPv4 network %q: %v", network, err))
		} else {
			routes, rerr := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: ipnet}, netlink.RT_FILTER_DST)
			if rerr != nil {
				errors = append(errors, fmt.Sprintf("IPv4 route lookup failed: %v", rerr))
			} else if len(routes) == 0 {
				errors = append(errors, fmt.Sprintf("IPv4 route for %s not found", network))
			} else if ifaceIndex > 0 {
				foundCorrectIface := false
				for _, r := range routes {
					if r.LinkIndex == ifaceIndex {
						foundCorrectIface = true
						break
					}
				}
				if !foundCorrectIface {
					errors = append(errors, fmt.Sprintf("IPv4 route for %s not on expected interface (index %d)", network, ifaceIndex))
				}
			}
		}
	}

	if ipv6Network != "" {
		checked++
		_, ipnet, err := net.ParseCIDR(ipv6Network)
		if err != nil {
			errors = append(errors, fmt.Sprintf("invalid IPv6 network %q: %v", ipv6Network, err))
		} else {
			routes, rerr := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Dst: ipnet}, netlink.RT_FILTER_DST)
			if rerr != nil {
				errors = append(errors, fmt.Sprintf("IPv6 route lookup failed: %v", rerr))
			} else if len(routes) == 0 {
				errors = append(errors, fmt.Sprintf("IPv6 route for %s not found", ipv6Network))
			} else if ifaceIndex > 0 {
				foundCorrectIface := false
				for _, r := range routes {
					if r.LinkIndex == ifaceIndex {
						foundCorrectIface = true
						break
					}
				}
				if !foundCorrectIface {
					errors = append(errors, fmt.Sprintf("IPv6 route for %s not on expected interface (index %d)", ipv6Network, ifaceIndex))
				}
			}
		}
	}

	if checked == 0 {
		return HealthCheckResult{OK: false, Error: "no network configured to check"}
	}

	if len(errors) > 0 {
		return HealthCheckResult{OK: false, Error: strings.Join(errors, "; ")}
	}

	return HealthCheckResult{OK: true, Message: fmt.Sprintf("flannel routes present (%d networks checked)", checked)}
}
