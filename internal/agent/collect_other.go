//go:build !windows

package agent

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

// The non-Windows collector exists so the agent can be developed and
// demonstrated on Linux. It reports system info, CPU, memory and disks.
type collector struct {
	mu                  sync.Mutex
	prevIdle, prevTotal uint64
}

func newCollector() *collector {
	c := &collector{}
	c.cpuPercent() // prime the delta
	return c
}

func (c *collector) systemInfo() protocol.SystemInfo {
	h, _ := os.Hostname()
	info := protocol.SystemInfo{Hostname: h, OS: runtime.GOOS, OSVersion: osRelease(), CPUs: runtime.NumCPU()}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(data)); len(f) > 0 {
			if up, err := strconv.ParseFloat(f[0], 64); err == nil {
				info.BootTime = time.Now().Add(-time.Duration(up) * time.Second).UTC().Truncate(time.Second)
			}
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
				info.IPs = append(info.IPs, ipn.IP.String())
			}
		}
	}
	return info
}

func osRelease() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return runtime.GOOS
}

func (c *collector) cpuPercent() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dt, di := total-c.prevTotal, idle-c.prevIdle
	c.prevTotal, c.prevIdle = total, idle
	if dt == 0 {
		return 0
	}
	return 100 * float64(dt-di) / float64(dt)
}

func memInfo() (total, used uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	vals := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(strings.Fields(v)[0], 10, 64)
		vals[k] = n * 1024
	}
	total = vals["MemTotal"]
	avail := vals["MemAvailable"]
	if avail > total {
		avail = total
	}
	return total, total - avail
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "vfat": true, "ntfs": true, "apfs": true, "overlay": true}

func disks() []protocol.Disk {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []protocol.Disk
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFS[f[2]] || seen[f[0]] {
			continue
		}
		seen[f[0]] = true
		var st syscall.Statfs_t
		if syscall.Statfs(f[1], &st) != nil || st.Blocks == 0 {
			continue
		}
		bs := uint64(st.Bsize)
		out = append(out, protocol.Disk{Name: f[1], Label: f[0], FS: f[2], Total: st.Blocks * bs, Free: st.Bavail * bs})
	}
	return out
}

func (c *collector) collect(ctx context.Context, since time.Time) *protocol.Heartbeat {
	total, used := memInfo()
	return &protocol.Heartbeat{
		System: c.systemInfo(),
		Metrics: protocol.Metrics{
			CPUPercent:  c.cpuPercent(),
			MemTotal:    total,
			MemUsed:     used,
			Disks:       disks(),
			CollectedAt: time.Now().UTC(),
		},
		Connections: tcpConnections(),
	}
}

// tcpConnections reads /proc/net/tcp{,6}. Inbound connections to a local
// listening port are reported once per client (remote port 0); outgoing
// ones once per remote endpoint. Process names are not resolved here.
func tcpConnections() []protocol.Connection {
	type row struct {
		local, remote net.IP
		lport, rport  int
		state         string
	}
	var rows []row
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || (f[3] != "0A" && f[3] != "01") {
				continue
			}
			lip, lport, ok1 := parseProcAddr(f[1])
			rip, rport, ok2 := parseProcAddr(f[2])
			if ok1 && ok2 {
				rows = append(rows, row{lip, rip, lport, rport, f[3]})
			}
		}
	}
	listen := map[int]bool{}
	for _, r := range rows {
		if r.state == "0A" {
			listen[r.lport] = true
		}
	}
	seen := map[string]bool{}
	var out []protocol.Connection
	add := func(key string, c protocol.Connection) {
		if !seen[key] && len(seen) < 1000 {
			seen[key] = true
			out = append(out, c)
		}
	}
	for _, r := range rows {
		switch {
		case r.state == "0A":
			add(fmt.Sprintf("L|%d", r.lport), protocol.Connection{State: protocol.ConnListen, LocalPort: r.lport})
		case r.remote.IsLoopback():
		case listen[r.lport]:
			add(fmt.Sprintf("I|%s|%d", r.remote, r.lport), protocol.Connection{State: protocol.ConnEstablished, LocalPort: r.lport, RemoteAddr: r.remote.String()})
		default:
			add(fmt.Sprintf("E|%s|%d", r.remote, r.rport), protocol.Connection{State: protocol.ConnEstablished, RemoteAddr: r.remote.String(), RemotePort: r.rport})
		}
	}
	return out
}

// parseProcAddr decodes "0100007F:1F90" (little-endian 32-bit words).
func parseProcAddr(s string) (net.IP, int, bool) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(hexIP)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, int(port), true
}
