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

package etcd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/subnet"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	log "k8s.io/klog/v2"
)

const (
	raceRetries = 10
	subnetTTL   = 24 * time.Hour
)

var (
	errInterrupted   = errors.New("interrupted")
	errCanceled      = errors.New("canceled")
	errUnimplemented = errors.New("unimplemented")
)

type LocalManager struct {
	registry               Registry
	previousSubnet         ip.IP4Net
	previousIPv6Subnet     ip.IP6Net
	subnetLeaseRenewMargin int
}

type watchCursor struct {
	index int64
}

func isErrEtcdNodeExist(e error) bool {
	if e == nil {
		return false
	}
	return e == rpctypes.ErrDuplicateKey
}

func isErrEtcdNodeNotFound(e error) bool {
	if e == nil {
		return false
	}
	return e == rpctypes.ErrGRPCKeyNotFound
}

func (c watchCursor) String() string {
	return strconv.FormatInt(c.index, 10)
}

func NewLocalManager(ctx context.Context, config *EtcdConfig, prevSubnet ip.IP4Net, prevIPv6Subnet ip.IP6Net, subnetLeaseRenewMargin int) (subnet.Manager, error) {
	r, err := newEtcdSubnetRegistry(ctx, config, nil)
	if err != nil {
		return nil, err
	}
	return newLocalManager(r, prevSubnet, prevIPv6Subnet, subnetLeaseRenewMargin), nil
}

func newLocalManager(r Registry, prevSubnet ip.IP4Net, prevIPv6Subnet ip.IP6Net, subnetLeaseRenewMargin int) subnet.Manager {
	return &LocalManager{
		registry:               r,
		previousSubnet:         prevSubnet,
		previousIPv6Subnet:     prevIPv6Subnet,
		subnetLeaseRenewMargin: subnetLeaseRenewMargin,
	}
}

func (m *LocalManager) GetStoredMacAddresses(ctx context.Context) (string, string) {
	return "", ""
}

func (m *LocalManager) GetStoredPublicIP(ctx context.Context) (string, string) {
	return "", ""
}

func (m *LocalManager) GetNetworkConfig(ctx context.Context) (*subnet.Config, error) {
	cfg, err := m.registry.getNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	config, err := subnet.ParseConfig(cfg)
	if err != nil {
		return nil, err
	}
	err = subnet.CheckNetworkConfig(config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (m *LocalManager) AcquireLease(ctx context.Context, attrs *lease.LeaseAttrs) (*lease.Lease, error) {
	config, err := m.GetNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	for i := 0; i < raceRetries; i++ {
		l, err := m.tryAcquireLease(ctx, config, attrs.PublicIP, attrs)
		switch err {
		case nil:
			return l, nil
		case errTryAgain:
			continue
		default:
			return nil, err
		}
	}

	return nil, errors.New("max retries reached trying to acquire a subnet")
}

func findLeaseByIP(leases []lease.Lease, pubIP ip.IP4) *lease.Lease {
	for _, l := range leases {
		if pubIP == l.Attrs.PublicIP {
			return &l
		}
	}

	return nil
}

func findLeaseBySubnet(leases []lease.Lease, subnet ip.IP4Net) *lease.Lease {
	for _, l := range leases {
		if subnet.Equal(l.Subnet) {
			return &l
		}
	}

	return nil
}

func (m *LocalManager) tryAcquireLease(ctx context.Context, config *subnet.Config, extIaddr ip.IP4, attrs *lease.LeaseAttrs) (*lease.Lease, error) {
	leases, _, err := m.registry.getSubnets(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	if l := findLeaseByIP(leases, extIaddr); l != nil {
		if isSubnetConfigCompat(config, l.Subnet) && isIPv6SubnetConfigCompat(config, l.IPv6Subnet) {
			if !l.Expiration.IsZero() && l.Expiration.Before(now) {
				log.Warningf("Found expired lease (ip: %v ipv6: %v) for current IP (%v), deleting before reusing", l.Subnet, l.IPv6Subnet, extIaddr)
				if err := m.registry.deleteSubnet(ctx, l.Subnet, l.IPv6Subnet); err != nil {
					return nil, err
				}
				time.Sleep(200 * time.Millisecond)
			} else {
				log.Infof("Found lease (ip: %v ipv6: %v) for current IP (%v), reusing", l.Subnet, l.IPv6Subnet, extIaddr)

				ttl := time.Duration(0)
				if !l.Expiration.IsZero() {
					ttl = subnetTTL
				}
				exp, err := m.registry.updateSubnet(ctx, l.Subnet, l.IPv6Subnet, attrs, ttl, 0)
				if err != nil {
					return nil, err
				}

				l.Attrs = *attrs
				l.Expiration = exp
				return l, nil
			}
		} else {
			log.Infof("Found lease (%+v) for current IP (%v) but not compatible with current config, deleting", l, extIaddr)
			if err := m.registry.deleteSubnet(ctx, l.Subnet, l.IPv6Subnet); err != nil {
				return nil, err
			}
		}
	}

	var sn ip.IP4Net
	var sn6 ip.IP6Net
	if !m.previousSubnet.Empty() {
		cachedLease := findLeaseBySubnet(leases, m.previousSubnet)
		if cachedLease == nil {
			directLease, _, derr := m.registry.getSubnet(ctx, m.previousSubnet, m.previousIPv6Subnet)
			if derr == nil && directLease != nil {
				log.Warningf("Previous subnet %v found in etcd but not in cache, cache was stale. Not reusing.", m.previousSubnet)
			} else if derr == nil && directLease == nil {
				if isSubnetConfigCompat(config, m.previousSubnet) && isIPv6SubnetConfigCompat(config, m.previousIPv6Subnet) {
					log.Infof("Found previously leased subnet (%v), verified available in etcd, reusing", m.previousSubnet)
					sn = m.previousSubnet
					sn6 = m.previousIPv6Subnet
				}
			} else if isErrEtcdNodeNotFound(derr) {
				if isSubnetConfigCompat(config, m.previousSubnet) && isIPv6SubnetConfigCompat(config, m.previousIPv6Subnet) {
					log.Infof("Found previously leased subnet (%v), verified available in etcd, reusing", m.previousSubnet)
					sn = m.previousSubnet
					sn6 = m.previousIPv6Subnet
				}
			} else {
				log.Warningf("Failed to verify previous subnet %v availability in etcd: %v", m.previousSubnet, derr)
			}
		} else if !cachedLease.Expiration.IsZero() && cachedLease.Expiration.Before(now) {
			log.Warningf("Found expired previous subnet (%v), deleting before reusing", m.previousSubnet)
			if err := m.registry.deleteSubnet(ctx, m.previousSubnet, m.previousIPv6Subnet); err != nil {
				return nil, err
			}
			time.Sleep(500 * time.Millisecond)
			if isSubnetConfigCompat(config, m.previousSubnet) && isIPv6SubnetConfigCompat(config, m.previousIPv6Subnet) {
				sn = m.previousSubnet
				sn6 = m.previousIPv6Subnet
			}
		}
	}

	if sn.Empty() {
		sn, sn6, err = m.allocateSubnet(config, leases)
		if err != nil {
			return nil, err
		}
	}

	exp, err := m.registry.createSubnet(ctx, sn, sn6, attrs, subnetTTL)
	switch {
	case err == nil:
		log.Infof("Allocated lease (ip: %v ipv6: %v) to current node (%v) ", sn, sn6, extIaddr)
		return &lease.Lease{
			EnableIPv4: true,
			Subnet:     sn,
			EnableIPv6: !sn6.Empty(),
			IPv6Subnet: sn6,
			Attrs:      *attrs,
			Expiration: exp,
		}, nil
	case isErrEtcdNodeExist(err):
		return nil, errTryAgain
	default:
		return nil, err
	}
}

func (m *LocalManager) allocateSubnet(config *subnet.Config, leases []lease.Lease) (ip.IP4Net, ip.IP6Net, error) {
	log.Infof("Picking subnet in range %s ... %s", config.SubnetMin, config.SubnetMax)
	if config.EnableIPv6 {
		log.Infof("Picking ipv6 subnet in range %s ... %s", config.IPv6SubnetMin, config.IPv6SubnetMax)
	}

	var availableIPs []ip.IP4
	var availableIPv6s []*ip.IP6
	now := time.Now()

	sn := ip.IP4Net{IP: config.SubnetMin, PrefixLen: config.SubnetLen}
	var sn6 ip.IP6Net
	if config.EnableIPv6 {
		sn6 = ip.IP6Net{IP: config.IPv6SubnetMin, PrefixLen: config.IPv6SubnetLen}
	}

OuterLoop:
	for ; sn.IP <= config.SubnetMax && len(availableIPs) < 100; sn = sn.Next() {
		for _, l := range leases {
			if sn.Overlaps(l.Subnet) {
				if !l.Expiration.IsZero() && l.Expiration.Before(now) {
					log.V(2).Infof("Ignoring expired lease %v (expired at %v)", l.Subnet, l.Expiration)
					continue
				}
				continue OuterLoop
			}
		}
		availableIPs = append(availableIPs, sn.IP)
	}

	if !sn6.Empty() {
	OuterLoopv6:
		for ; sn6.IP.Cmp(config.IPv6SubnetMax) <= 0 && len(availableIPv6s) < 100; sn6 = sn6.Next() {
			for _, l := range leases {
				if sn6.Overlaps(l.IPv6Subnet) {
					if !l.Expiration.IsZero() && l.Expiration.Before(now) {
						log.V(2).Infof("Ignoring expired IPv6 lease %v (expired at %v)", l.IPv6Subnet, l.Expiration)
						continue
					}
					continue OuterLoopv6
				}
			}
			availableIPv6s = append(availableIPv6s, sn6.IP)
		}
	}

	if len(availableIPs) == 0 || (!sn6.Empty() && len(availableIPv6s) == 0) {
		return ip.IP4Net{}, ip.IP6Net{}, errors.New("out of subnets")
	} else {
		i := randInt(0, len(availableIPs))
		ipnet := ip.IP4Net{IP: availableIPs[i], PrefixLen: config.SubnetLen}

		if sn6.Empty() {
			return ipnet, ip.IP6Net{}, nil
		}
		i = randInt(0, len(availableIPv6s))
		return ipnet, ip.IP6Net{IP: availableIPv6s[i], PrefixLen: config.IPv6SubnetLen}, nil
	}
}

func (m *LocalManager) RenewLease(ctx context.Context, lease *lease.Lease) error {
	exp, err := m.registry.updateSubnet(ctx, lease.Subnet, lease.IPv6Subnet, &lease.Attrs, subnetTTL, 0)
	if err != nil {
		return err
	}

	lease.Expiration = exp
	return nil
}

func getNextIndex(cursor interface{}) (int64, error) {
	nextIndex := int64(0)

	if wc, ok := cursor.(watchCursor); ok {
		nextIndex = wc.index
	} else if s, ok := cursor.(string); ok {
		var err error
		nextIndex, err = strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse cursor: %v", err)
		}
	} else {
		return 0, fmt.Errorf("internal error: watch cursor is of unknown type")
	}

	return nextIndex + 1, nil
}

func (m *LocalManager) leaseWatchReset(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net) (lease.LeaseWatchResult, error) {
	l, index, err := m.registry.getSubnet(ctx, sn, sn6)
	if err != nil {
		return lease.LeaseWatchResult{}, err
	}

	return lease.LeaseWatchResult{
		Snapshot: []lease.Lease{*l},
		Cursor:   watchCursor{index},
	}, nil
}

func (m *LocalManager) WatchLease(ctx context.Context, sn ip.IP4Net, sn6 ip.IP6Net, receiver chan []lease.LeaseWatchResult) error {
	wr, err := m.leaseWatchReset(ctx, sn, sn6)
	if err != nil {
		return err
	}

	log.Info("manager.WatchLease: sending reset results...")
	//send the result of leaseWatchResult to allow the listener
	//to catch-up to the current state
	receiver <- []lease.LeaseWatchResult{wr}

	nextIndex, err := getNextIndex(wr.Cursor)
	if err != nil {
		return err
	}

	err = m.registry.watchSubnet(ctx, nextIndex, sn, sn6, receiver)
	if err != nil {
		return err
	}
	return nil
}

func (m *LocalManager) WatchLeases(ctx context.Context, receiver chan []lease.LeaseWatchResult) error {
	wr, err := m.registry.leasesWatchReset(ctx)
	if err != nil {
		return err
	}

	// send the result of leasesWatchReset to the listener
	// to catch-up on the state if the registry
	// before starting to watch changes
	receiver <- []lease.LeaseWatchResult{wr}

	nextIndex, err := getNextIndex(wr.Cursor)
	if err != nil {
		return err
	}

	err = m.registry.watchSubnets(ctx, receiver, nextIndex)
	if err != nil {
		return err
	}
	return nil
}

func (m *LocalManager) CompleteLease(ctx context.Context, myLease *lease.Lease, wg *sync.WaitGroup) error {
	evts := make(chan lease.Event)

	wg.Add(1)
	go func() {
		l := myLease
		subnet.WatchLease(ctx, m, l.Subnet, l.IPv6Subnet, evts)
		wg.Done()
	}()

	renewMargin := time.Duration(m.subnetLeaseRenewMargin) * time.Minute
	dur := time.Until(myLease.Expiration) - renewMargin
	renewFailures := 0
	const maxRenewFailures = 3

	for {
		select {
		case <-time.After(dur):
			err := m.RenewLease(ctx, myLease)
			if err != nil {
				renewFailures++
				log.Errorf("Error renewing lease (attempt %d): %v", renewFailures, err)

				if renewFailures >= maxRenewFailures {
					log.Warning("Max renewal failures reached, attempting to release and re-acquire lease")
					if rerr := m.registry.deleteSubnet(ctx, myLease.Subnet, myLease.IPv6Subnet); rerr != nil {
						log.Errorf("Failed to release expired lease: %v", rerr)
					}

					time.Sleep(500 * time.Millisecond)

					newLease, aerr := m.AcquireLease(ctx, &myLease.Attrs)
					if aerr != nil {
						log.Errorf("Failed to re-acquire lease: %v", aerr)
						dur = time.Minute
						continue
					}

					*myLease = *newLease
					renewFailures = 0
					dur = time.Until(myLease.Expiration) - renewMargin
					log.Infof("Successfully re-acquired lease: %v", myLease.Subnet)
					continue
				}

				dur = time.Minute
				continue
			}

			renewFailures = 0
			log.Info("Lease renewed, new expiration: ", myLease.Expiration)
			dur = time.Until(myLease.Expiration) - renewMargin

		case e, ok := <-evts:
			if !ok {
				log.Infof("Stopped monitoring lease")
				return errCanceled
			}
			switch e.Type {
			case lease.EventAdded:
				myLease.Expiration = e.Lease.Expiration
				dur = time.Until(myLease.Expiration) - renewMargin
				log.Infof("Waiting for %s to renew lease", dur)

			case lease.EventRemoved:
				log.Warning("Lease has been revoked, attempting to release and re-acquire")
				_ = m.registry.deleteSubnet(ctx, myLease.Subnet, myLease.IPv6Subnet)

				time.Sleep(500 * time.Millisecond)

				newLease, aerr := m.AcquireLease(ctx, &myLease.Attrs)
				if aerr != nil {
					log.Errorf("Failed to re-acquire lease after revocation: %v", aerr)
					return errInterrupted
				}
				*myLease = *newLease
				renewFailures = 0
				dur = time.Until(myLease.Expiration) - renewMargin
				log.Infof("Successfully re-acquired lease after revocation: %v", myLease.Subnet)
			}
		}
	}
}

func isIndexTooSmall(err error) bool {
	return err == rpctypes.ErrGRPCCompacted
}

func isSubnetConfigCompat(config *subnet.Config, sn ip.IP4Net) bool {
	if sn.IP < config.SubnetMin || sn.IP > config.SubnetMax {
		return false
	}

	return sn.PrefixLen == config.SubnetLen
}

func isIPv6SubnetConfigCompat(config *subnet.Config, sn6 ip.IP6Net) bool {
	if !config.EnableIPv6 {
		return sn6.Empty()
	}
	if sn6.Empty() || sn6.IP.Cmp(config.IPv6SubnetMin) < 0 || sn6.IP.Cmp(config.IPv6SubnetMax) > 0 {
		return false
	}

	return sn6.PrefixLen == config.IPv6SubnetLen
}

func (m *LocalManager) Name() string {
	previousSubnet := m.previousSubnet.String()
	if m.previousSubnet.Empty() {
		previousSubnet = "None"
	}
	return fmt.Sprintf("Etcd Local Manager with Previous Subnet: %s", previousSubnet)
}

func (m *LocalManager) getLeasesSnapshot(ctx context.Context) ([]lease.Lease, int64, error) {
	return m.registry.getSubnets(ctx)
}

// For etcd subnet manager, the file never changes so we just write it once at startup
func (m *LocalManager) HandleSubnetFile(path string, config *subnet.Config, ipMasq bool, sn ip.IP4Net, ipv6sn ip.IP6Net, mtu int) error {
	return subnet.WriteSubnetFile(path, config, ipMasq, sn, ipv6sn, mtu)
}
