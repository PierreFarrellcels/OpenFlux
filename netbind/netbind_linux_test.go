//go:build linux

package netbind

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The kernel's own route dump, as /proc/net/route writes it.
const routeDump = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0102A850	0003	0	0	100	00000000	0	0	0
eth1	0000060A	0106060A	0003	0	0	100	0000FF00	0	0	0
eth0	0020A850	00000000	0001	0	0	0	00FFFFFF	0	0	0
`

func TestDefaultDeviceReadsTheRouteTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(routeDump), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := defaultDeviceFrom(path, true); got != "eth0" {
		t.Fatalf("default device %q, want eth0", got)
	}
	// A route to a network is not the default one.
	if got := defaultDeviceFrom(path, true); got == "eth1" {
		t.Fatal("took a network route for the default one")
	}
	if got := defaultDeviceFrom(filepath.Join(t.TempDir(), "none"), true); got != "" {
		t.Fatalf("missing file gave %q", got)
	}
}

func TestDefaultDeviceSkipsLoopback(t *testing.T) {
	dump := "Iface\tDestination\tGateway \tFlags\n" +
		"lo\t00000000\t00000000\t0001\n" +
		"eth0\t00000000\t0102A850\t0003\n"
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := defaultDeviceFrom(path, true); got != "eth0" {
		t.Fatalf("default device %q, want eth0", got)
	}
}

func TestDefaultDeviceIPv6(t *testing.T) {
	dump := "Iface\tDestination\tNext Hop\tFlags\tMetric\n" +
		"lo\t00000000000000000000000000000000\t00000000000000000000000000000000\t00000001\t0\n" +
		"eth0\t00000000000000000000000000000000\tfe800000000000000000000000000001\t00000003\t1024\n"
	path := filepath.Join(t.TempDir(), "route6")
	if err := os.WriteFile(path, []byte(dump), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := defaultDeviceFrom(path, false); got != "eth0" {
		t.Fatalf("default device %q, want eth0", got)
	}
}

// The binding must let the carriers dial while the routes point elsewhere:
// a socket bound to the loopback device does not reach the outside world,
// and a bound dial to loopback still works.
func TestBindNamePinsSockets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SO_BINDTODEVICE needs root")
	}
	defer func() {
		current.Store(nil)
		boundName.Store(nil)
		boundIndex.Store(0)
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	index, err := BindName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if index == 0 || Device() != "lo" {
		t.Fatalf("bound to %q index %d", Device(), index)
	}
	if !Bound() {
		t.Fatal("not bound")
	}
	// Loopback stays where it is, so the IPC socket and the proxies work.
	c, err := Dialer(5*time.Second).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("loopback dial under the binding: %v", err)
	}
	c.Close()

	if _, err := BindName("nosuchdevice0"); err == nil || !strings.Contains(err.Error(), "nosuchdevice0") {
		t.Fatalf("binding to a missing device: %v", err)
	}
}
