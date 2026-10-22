//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/p1neappleXpress/OpenFlux/transport"
)

// fakeTransport stands in for a carrier: it hands back whatever Send got and
// answers every IPv4 packet with the given function.
type fakeTransport struct {
	sent    atomic.Int64
	onSend  func([]byte)
	receive func([]byte)
}

func (f *fakeTransport) Start() error      { return nil }
func (f *fakeTransport) Stop() error       { return nil }
func (f *fakeTransport) IsConnected() bool { return true }
func (f *fakeTransport) Stats() transport.TransportStats {
	return transport.TransportStats{Connected: true}
}
func (f *fakeTransport) Receive(callback func([]byte)) { f.receive = callback }
func (f *fakeTransport) Send(data []byte) error {
	f.sent.Add(1)
	if f.onSend != nil {
		f.onSend(data)
	}
	return nil
}

// The tun device takes packets the system routes into it and gives back what
// the transport delivers. Uses a test-only route, never the default one.
func TestTUNCarriesPacketsBothWays(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the tun device needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("no ping to make traffic")
	}

	trans := &fakeTransport{}
	client, err := NewTUNClient(trans, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetupInterface(); err != nil {
		t.Fatal(err)
	}
	// TEST-NET-2 through the device only: the default route stays as it is.
	if err := ip("route", "add", "198.18.0.0/15", "dev", client.name); err != nil {
		t.Fatal(err)
	}
	defer ip("route", "del", "198.18.0.0/15", "dev", client.name)

	client.Start()
	// Answer each echo request as the address the ping asked for.
	trans.onSend = func(pkt []byte) {
		if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != 1 || pkt[20] != 8 {
			return
		}
		reply := make([]byte, len(pkt))
		copy(reply, pkt)
		copy(reply[12:16], pkt[16:20])
		copy(reply[16:20], pkt[12:16])
		reply[20] = 0
		reply[10], reply[11] = 0, 0
		sum := uint32(0)
		for i := 0; i < 20; i += 2 {
			sum += uint32(reply[i])<<8 | uint32(reply[i+1])
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		reply[10], reply[11] = byte(^sum>>8), byte(^sum)
		reply[22], reply[23] = 0, 0
		sum = 0
		for i := 20; i+1 < len(reply); i += 2 {
			sum += uint32(reply[i])<<8 | uint32(reply[i+1])
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		reply[22], reply[23] = byte(^sum>>8), byte(^sum)
		if trans.receive != nil {
			trans.receive(reply)
		}
	}

	out, err := exec.Command("ping", "-c", "1", "-W", "3", "198.18.0.1").CombinedOutput()
	if err != nil {
		t.Fatalf("ping through the tun failed: %v\n%s", err, out)
	}
	if trans.sent.Load() == 0 {
		t.Fatal("the echo request never reached the transport")
	}
	if client.packetsIn.Load() == 0 {
		t.Fatal("the reply never came back to the device")
	}
}

func TestTUNNamesThePhysicalDevice(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("SO_BINDTODEVICE needs root")
	}
	client := &TUNClient{}
	if err := client.SaveDefault(); err != nil {
		t.Fatal(err)
	}
	if client.physical == "" || client.index == 0 {
		t.Fatalf("physical %q index %d", client.physical, client.index)
	}
}

// The default route goes into the device as two /1 routes and comes back out
// on Close, so a host is never left pointing at an interface that is gone.
func TestTUNDefaultRouteComesAndGoes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the tun device needs root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun")
	}
	client, err := NewTUNClient(&fakeTransport{}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetupInterface(); err != nil {
		t.Fatal(err)
	}
	// The device goes away with its routes: take the default only if this
	// host has nothing else on those prefixes, and put the old state back.
	// A test that fails here must not leave the machine offline.
	defer client.RestoreDefault()
	if err := client.ConfigureDefault(); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		out, err := exec.Command(ipPath(), "route", "show", prefix).CombinedOutput()
		if err != nil {
			t.Fatalf("ip route show %s: %v", prefix, err)
		}
		if !strings.Contains(string(out), client.name) {
			t.Fatalf("%s does not go through %s: %s", prefix, client.name, out)
		}
	}
	client.RestoreDefault()
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		out, _ := exec.Command(ipPath(), "route", "show", prefix).CombinedOutput()
		if strings.Contains(string(out), client.name) {
			t.Fatalf("%s still goes through %s after the restore: %s", prefix, client.name, out)
		}
	}
}
