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

package main

import (
	"fmt"
	"net"
)

func checkNetworkInterface(ifaceName string, ifaceIndex int) HealthCheckResult {
	if ifaceName == "" {
		return HealthCheckResult{OK: false, Error: "external interface not set"}
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("interface %q not found: %v", ifaceName, err)}
	}

	if iface.Flags&net.FlagUp == 0 {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("interface %q is not UP", ifaceName)}
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("failed to list addresses for %q: %v", ifaceName, err)}
	}
	if len(addrs) == 0 {
		return HealthCheckResult{OK: false, Error: fmt.Sprintf("interface %q has no IP addresses", ifaceName)}
	}

	return HealthCheckResult{OK: true, Message: fmt.Sprintf("interface %q is UP (index %d, MTU %d, %d addrs)", ifaceName, iface.Index, iface.MTU, len(addrs))}
}

func checkRoutingTable(network, ipv6Network string, ifaceIndex int) HealthCheckResult {
	return HealthCheckResult{OK: true, Message: "routing table check skipped on this platform"}
}
