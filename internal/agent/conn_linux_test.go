//go:build linux

package agent

import (
	"net"
	"testing"
)

func TestParseProcAddr(t *testing.T) {
	ip, port, ok := parseProcAddr("0100007F:1F90")
	if !ok || ip.String() != "127.0.0.1" || port != 8080 {
		t.Fatalf("got %v %d %v", ip, port, ok)
	}
}

func TestTCPConnectionsSeesListener(t *testing.T) {
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	for _, c := range tcpConnections() {
		if c.State == "listen" && c.LocalPort == port {
			return
		}
	}
	t.Fatalf("listener on %d not reported", port)
}
