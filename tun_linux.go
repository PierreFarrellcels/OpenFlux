//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/p1neappleXpress/OpenFlux/netbind"
	"github.com/p1neappleXpress/OpenFlux/network"
	"github.com/p1neappleXpress/OpenFlux/transport"
	"github.com/p1neappleXpress/OpenFlux/utils"
)

// The Linux full tunnel: a tun device takes the default route (two /1
// routes, as on the other platforms) and its IPv4 packets go straight to
// the transport, like the macOS utun client and the Windows Wintun one.
// The core's own sockets are bound to the real interface (netbind,
// SO_BINDTODEVICE), so the carriers never loop into the tunnel and no host
// bypass routes are needed. IPv6 is routed into the device too and dropped,
// so programs fall back to IPv4 instead of leaking past the tunnel. The
// routes go away with the device: closing its fd removes it.

const (
	tunDeviceName = "openflux0"
	tunLocalIPv4  = "10.10.10.2"

	// Every packet handed to the device needs room for the virtio header in
	// front of it (the tun package's own constant is unexported); reads get
	// the same headroom, which the kernel fills with the header too.
	tunHeadroom = 16
)

type TUNClient struct {
	trans transport.Transport
	dev   tun.Device
	name  string
	mtu   int

	physical string
	index    uint32

	packetsIn  atomic.Uint64
	packetsOut atomic.Uint64
	dropped6   atomic.Uint64
	closed     atomic.Bool
}

func NewTUNClient(trans transport.Transport, mtu int) (*TUNClient, error) {
	dev, err := tun.CreateTUN(tunDeviceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("не удалось создать устройство %s (нужны права root и /dev/net/tun): %w", tunDeviceName, err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("устройство %s: %w", tunDeviceName, err)
	}
	return &TUNClient{trans: trans, dev: dev, name: name, mtu: mtu}, nil
}

func (c *TUNClient) Name() string { return c.name + " (tun)" }

// Gateway names the real interface the carriers leave through.
func (c *TUNClient) Gateway() string { return "интерфейс " + c.physical }

// SaveDefault binds the core's sockets to the real interface, unless main
// did so before the transports started (it should: sockets opened before
// the binding would follow the default route into the tunnel).
func (c *TUNClient) SaveDefault() error {
	name, index, err := netbind.DefaultDevice()
	if err != nil {
		return err
	}
	c.physical, c.index = name, index
	if netbind.Bound() {
		return nil
	}
	_, err = netbind.BindName(name)
	return err
}

// SetupInterface gives the device its address, MTU and the up flag.
func (c *TUNClient) SetupInterface() error {
	if err := ip("link", "set", "dev", c.name, "mtu", strconv.Itoa(c.mtu), "up"); err != nil {
		return err
	}
	return ip("addr", "add", tunLocalIPv4+"/24", "dev", c.name)
}

// ConfigureDefault takes the default route: two /1 routes beat 0.0.0.0/0
// without touching it, so the real default stays for the bound sockets.
func (c *TUNClient) ConfigureDefault() error {
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := ip("route", "replace", prefix, "dev", c.name); err != nil {
			return err
		}
	}
	// IPv6 only to drop it; a system without IPv6 is fine as well.
	for _, prefix := range []string{"::/1", "8000::/1"} {
		_ = ip("-6", "route", "replace", prefix, "dev", c.name)
	}
	return nil
}

// Start runs the two forwarding loops.
func (c *TUNClient) Start() {
	c.trans.Receive(func(pkt []byte) {
		if c.closed.Load() {
			return
		}
		// <- : packet arrives from the tunnel / exit towards the device.
		network.LogPacket("TUN", network.DirInbound, pkt)
		out := make([]byte, tunHeadroom+len(pkt))
		copy(out[tunHeadroom:], pkt)
		if _, err := c.dev.Write([][]byte{out}, tunHeadroom); err != nil {
			utils.Debugf("[TUN] write: %v", err)
			return
		}
		c.packetsIn.Add(1)
	})
	go c.readFromTun()
	go c.report()
}

func (c *TUNClient) readFromTun() {
	batch := c.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, tunHeadroom+65535)
	}
	sizes := make([]int, batch)
	for !c.closed.Load() {
		n, err := c.dev.Read(bufs, sizes, tunHeadroom)
		if err != nil {
			if !c.closed.Load() {
				utils.Debugf("[TUN] read: %v", err)
			}
			return
		}
		// A GSO read may hand back several packets at once.
		for i := 0; i < n && i < len(bufs); i++ {
			if sizes[i] < 20 {
				continue
			}
			pkt := bufs[i][tunHeadroom : tunHeadroom+sizes[i]]
			if pkt[0]>>4 != 4 {
				c.dropped6.Add(1) // IPv6: routed here only to be dropped
				continue
			}
			out := make([]byte, len(pkt))
			copy(out, pkt)
			c.packetsOut.Add(1)
			// -> : packet leaves the device towards the tunnel / exit.
			network.LogPacket("TUN", network.DirOutbound, out)
			if err := c.trans.Send(out); err != nil {
				utils.Debugf("[TUN] trans.Send: %v", err)
			}
		}
	}
}

func (c *TUNClient) report() {
	for !c.closed.Load() {
		time.Sleep(time.Minute)
		utils.Debugf("[TUN] packets out=%d in=%d ipv6 dropped=%d", c.packetsOut.Load(), c.packetsIn.Load(), c.dropped6.Load())
	}
}

// Close removes the device, and with it its addresses and routes.
func (c *TUNClient) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	c.RestoreDefault()
	return c.dev.Close()
}

// RestoreDefault takes the tunnel's routes out before the device goes, so a
// host is not left pointing at an interface that no longer exists.
func (c *TUNClient) RestoreDefault() {
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_ = ip("route", "del", prefix, "dev", c.name)
	}
	for _, prefix := range []string{"::/1", "8000::/1"} {
		_ = ip("-6", "route", "del", prefix, "dev", c.name)
	}
}

func (c *TUNClient) purgeStaleHostRoutes() {}

// SocketWatcher waits for nothing on Linux: the carriers' sockets are bound
// to the real interface, so the default route can move at once.
type SocketWatcher struct{ onStable func() }

func NewSocketWatcher(gateway string, onStable func()) *SocketWatcher {
	return &SocketWatcher{onStable: onStable}
}

func (w *SocketWatcher) Start(interval time.Duration) { go w.onStable() }
func (w *SocketWatcher) Stop()                        {}

// ip runs iproute2. It is looked up by its usual places first: the core
// runs as root from a graphical prompt (pkexec), where PATH is a fixed
// minimal one and /usr/sbin may be missing.
func ip(args ...string) error {
	out, err := exec.Command(ipPath(), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ipPath() string {
	for _, p := range []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("ip"); err == nil {
		return p
	}
	return "ip"
}
