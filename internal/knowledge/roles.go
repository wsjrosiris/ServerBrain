// Package knowledge is ServerBrain's second brain: it learns facts about
// servers and the infrastructure from every heartbeat, keeps a server
// diary, and renders everything into an Obsidian vault.
package knowledge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wsjrosiris/serverbrain/internal/protocol"
)

// Role is something a server does, detected from services or ports.
type Role struct {
	Key   string `json:"key"`  // family, e.g. "web" - one role per family
	Name  string `json:"name"` // display name
	Via   string `json:"via"`  // evidence, e.g. "Dienst W3SVC"
	Order int    `json:"-"`
}

type serviceRule struct {
	match func(name string) bool
	key   string
	role  string
}

func exact(n string) func(string) bool { return func(s string) bool { return s == n } }
func prefix(p string) func(string) bool {
	return func(s string) bool { return strings.HasPrefix(s, p) }
}
func oneOf(ns ...string) func(string) bool {
	return func(s string) bool {
		for _, n := range ns {
			if s == n {
				return true
			}
		}
		return false
	}
}

var serviceRules = []serviceRule{
	{exact("ntds"), "ad", "Active Directory Domain Controller"},
	{exact("dns"), "dns", "DNS-Server"},
	{exact("dhcpserver"), "dhcp", "DHCP-Server"},
	{exact("certsvc"), "adcs", "Zertifizierungsstelle (AD CS)"},
	{exact("w3svc"), "web", "Webserver (IIS)"},
	{exact("ftpsvc"), "ftp", "FTP-Server (IIS)"},
	{oneOf("mssqlserver"), "mssql", "SQL Server"},
	{prefix("mssql$"), "mssql", "SQL Server"},
	{oneOf("reportserver", "sqlserverreportingservices"), "ssrs", "SQL Reporting Services"},
	{prefix("msexchange"), "exchange", "Exchange Server"},
	{exact("vmms"), "hyperv", "Hyper-V Host"},
	{exact("clussvc"), "cluster", "Failover Cluster"},
	{exact("wsusservice"), "wsus", "WSUS"},
	{oneOf("tssdis", "rdms", "tscpubrpc"), "rds", "Remote Desktop Services"},
	{oneOf("docker", "com.docker.service"), "docker", "Docker"},
	{prefix("veeam"), "backup", "Veeam Backup"},
	{exact("sshd"), "ssh", "OpenSSH-Server"},
	{oneOf("nginx"), "web", "Webserver (nginx)"},
	{oneOf("apache2", "httpd"), "web", "Webserver (Apache)"},
	{oneOf("postgresql"), "postgres", "PostgreSQL"},
	{oneOf("mysql", "mariadb", "mysqld"), "mysql", "MySQL/MariaDB"},
}

type portRule struct {
	ports []int
	key   string
	role  string
	// windows=false: only for non-Windows (e.g. 445 is on every Windows box)
	notWindows bool
}

var portRules = []portRule{
	{[]int{88, 389}, "ad", "Domain Controller (Kerberos/LDAP)", false},
	{[]int{53}, "dns", "DNS-Server", false},
	{[]int{80}, "web", "Webserver", false},
	{[]int{443}, "web", "Webserver", false},
	{[]int{1433}, "mssql", "SQL Server", false},
	{[]int{3306}, "mysql", "MySQL/MariaDB", false},
	{[]int{5432}, "postgres", "PostgreSQL", false},
	{[]int{6379}, "redis", "Redis", false},
	{[]int{27017}, "mongodb", "MongoDB", false},
	{[]int{25}, "smtp", "Mailserver (SMTP)", false},
	{[]int{5672}, "rabbitmq", "RabbitMQ", false},
	{[]int{9200}, "elastic", "Elasticsearch", false},
	{[]int{2049}, "nfs", "NFS-Server", false},
	{[]int{445}, "smb", "Dateiserver (SMB)", true},
}

var portNames = map[int]string{
	20: "FTP-Daten", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3",
	123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos-PW",
	587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS", 1433: "SQL Server", 1434: "SQL Browser", 2049: "NFS",
	3268: "Global Catalog", 3269: "Global Catalog SSL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5672: "AMQP", 5985: "WinRM", 5986: "WinRM HTTPS", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
	9200: "Elasticsearch", 9389: "AD Web Services", 27017: "MongoDB",
}

// PortName returns "1433 (SQL Server)" or just "8123".
func PortName(port int) string {
	if n, ok := portNames[port]; ok {
		return fmt.Sprintf("%d (%s)", port, n)
	}
	return fmt.Sprint(port)
}

// BenignStoppedServices are automatic services that are routinely stopped
// on healthy Windows servers (trigger-started or delayed services).
var BenignStoppedServices = map[string]bool{
	"gupdate": true, "gupdatem": true, "edgeupdate": true, "edgeupdatem": true,
	"mapsbroker": true, "sppsvc": true, "remoteregistry": true, "cdpsvc": true,
	"tiledatamodelsvc": true, "wbiosrvc": true, "clr_optimization_v4.0.30319_32": true,
	"clr_optimization_v4.0.30319_64": true, "onesyncsvc": true, "shellhwdetection": true,
	"sysmain": true, "wuauserv": true, "bits": true, "trustedinstaller": true,
}

// IsAutoStart reports whether a service start type is automatic.
func IsAutoStart(startType string) bool {
	return strings.HasPrefix(strings.ToLower(startType), "auto")
}

// DetectRoles derives server roles from installed services and listening
// ports. Service evidence wins over port evidence within a family.
func DetectRoles(hb *protocol.Heartbeat) []Role {
	byKey := map[string]Role{}
	order := 0
	for _, svc := range hb.Services {
		name := strings.ToLower(svc.Name)
		if strings.EqualFold(svc.StartType, "disabled") {
			continue
		}
		for _, r := range serviceRules {
			if r.match(name) {
				if _, ok := byKey[r.key]; !ok {
					order++
					byKey[r.key] = Role{Key: r.key, Name: r.role, Via: "Dienst " + svc.Name, Order: order}
				}
				break
			}
		}
	}
	listen := map[int]bool{}
	for _, c := range hb.Connections {
		if c.State == protocol.ConnListen {
			listen[c.LocalPort] = true
		}
	}
	for _, r := range portRules {
		if r.notWindows && hb.System.OS == "windows" {
			continue
		}
		all := true
		for _, p := range r.ports {
			all = all && listen[p]
		}
		if _, ok := byKey[r.key]; all && !ok {
			order++
			ports := make([]string, len(r.ports))
			for i, p := range r.ports {
				ports[i] = fmt.Sprint(p)
			}
			byKey[r.key] = Role{Key: r.key, Name: r.role, Via: "Port " + strings.Join(ports, "+"), Order: order}
		}
	}
	out := make([]Role, 0, len(byKey))
	for _, r := range byKey {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

// RoleCriticalServices are services whose state matters for detected roles;
// they are listed in the server note even when they run normally.
var roleCriticalServices = map[string]bool{
	"ntds": true, "dns": true, "dhcpserver": true, "certsvc": true, "w3svc": true, "was": true,
	"mssqlserver": true, "sqlserveragent": true, "msexchangeis": true, "msexchangetransport": true,
	"vmms": true, "clussvc": true, "wsusservice": true, "docker": true, "netlogon": true, "kdc": true,
}

// IsRoleCritical reports whether a service is important for a server role.
func IsRoleCritical(name string) bool {
	n := strings.ToLower(name)
	return roleCriticalServices[n] || strings.HasPrefix(n, "mssql$") || strings.HasPrefix(n, "sqlagent$")
}
