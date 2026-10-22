//go:build linux

package netbind

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// SO_BINDTODEVICE pins a socket to one interface whatever the routes say.
// Linux has no GetBestInterfaceEx, so the default device is read from the
// route table's own files (/proc/net/route, then route6): the same answer
// "ip route get" would give, without running anything.

var boundName atomic.Pointer[string]

// DefaultDevice is the interface that carries the default route now, with
// its index.
func DefaultDevice() (string, uint32, error) {
	if name := Device(); name != "" {
		return name, Index(), nil
	}
	name, err := defaultDevice()
	if err != nil {
		return "", 0, err
	}
	index, err := indexOf(name)
	if err != nil {
		return "", 0, err
	}
	return name, index, nil
}

// Device is the interface sockets are bound to, "" when none.
func Device() string {
	if p := boundName.Load(); p != nil {
		return *p
	}
	return ""
}

var boundIndex atomic.Uint32

// Index is the index of the interface sockets are bound to, 0 when none.
func Index() uint32 { return boundIndex.Load() }

// BindName binds every new socket of the core to the interface called name
// and returns its index.
func BindName(name string) (uint32, error) {
	index, err := indexOf(name)
	if err != nil {
		return 0, err
	}
	install(func(network, address string, c syscall.RawConn) error {
		// Loopback (the IPC socket, local proxies) must stay where it is.
		if host, _, err := net.SplitHostPort(address); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				return nil
			}
		}
		var err error
		if cerr := c.Control(func(fd uintptr) {
			if e := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name); e != nil {
				err = fmt.Errorf("привязка к интерфейсу %s: %v", name, e)
			}
		}); cerr != nil {
			return cerr
		}
		return err
	})
	boundName.Store(&name)
	boundIndex.Store(index)
	return index, nil
}

// BindDefault binds every new socket of the core to the interface that
// carries the default route now, before anything moves it.
func BindDefault() (uint32, error) {
	name, err := defaultDevice()
	if err != nil {
		return 0, err
	}
	return BindName(name)
}

// defaultDevice reads the default route's device from the kernel's route
// tables: IPv4 first, IPv6 when there is no IPv4 default.
func defaultDevice() (string, error) {
	if name := defaultDeviceFrom("/proc/net/route", true); name != "" {
		return name, nil
	}
	if name := defaultDeviceFrom("/proc/net/route6", false); name != "" {
		return name, nil
	}
	return "", errors.New("нет маршрута в интернет")
}

// defaultDeviceFrom parses the kernel's route dump: IPv4 lines are
// "Iface Destination Gateway Flags …" with the destination in hex and the
// RTF_GATEWAY bit (0x2) set; IPv6 lines name the destination as ::/0.
func defaultDeviceFrom(path string, v4 bool) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		iface := fields[0]
		if iface == "lo" {
			continue
		}
		if v4 {
			if fields[1] != "00000000" {
				continue
			}
			flags, err := strconv.ParseUint(fields[3], 16, 32)
			if err != nil || flags&0x2 == 0 {
				continue
			}
		} else if fields[1] != "00000000000000000000000000000000" {
			continue
		}
		return iface
	}
	return ""
}

// indexOf is the interface's kernel index, which the tun device's routes
// are compared against.
func indexOf(name string) (uint32, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("интерфейс %s: %w", name, err)
	}
	return uint32(iface.Index), nil
}
