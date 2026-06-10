package lib

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type VulnInfo struct {
	CVEID       string
	Description string
	Severity    string
	Reference   string
}

type ServiceInfo struct {
	Port        int
	Protocol    string
	ServiceName string
	Banner      string
	Headers     map[string]string
	Vulns       []VulnInfo
	Fingerprint string
}

type ServiceDetectResult struct {
	Target   string
	Services []ServiceInfo
	Elapsed  time.Duration
}

type ServiceDetector struct {
	Timeout time.Duration
}

func NewServiceDetector(TimeoutSec int) *ServiceDetector {
	return &ServiceDetector{Timeout: time.Duration(TimeoutSec) * time.Second}
}

var VulnDatabase = map[string][]VulnInfo{
	"FTP": {
		{CVEID: "CVE-2011-2523", Description: "vsftpd 2.3.4 backdoor RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"},
		{CVEID: "CVE-2015-3306", Description: "ProFTPd mod_copy unauthenticated file copy", Severity: "HIGH", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-3306"},
	},
	"SSH": {
		{CVEID: "CVE-2023-38408", Description: "OpenSSH ssh-agent RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"},
		{CVEID: "CVE-2024-6387", Description: "OpenSSH regreSSHion race condition RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"},
	},
	"HTTP": {
		{CVEID: "CVE-2021-41773", Description: "Apache 2.4.49 path traversal RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
		{CVEID: "CVE-2022-22965", Description: "Spring4Shell RCE via data binding", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"},
	},
	"HTTPS": {
		{CVEID: "CVE-2014-0160", Description: "Heartbleed OpenSSL memory disclosure", Severity: "HIGH", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"},
		{CVEID: "CVE-2014-0224", Description: "OpenSSL CCS injection", Severity: "HIGH", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2014-0224"},
	},
	"SMB": {
		{CVEID: "CVE-2017-0144", Description: "EternalBlue SMBv1 RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"},
		{CVEID: "CVE-2020-0796", Description: "SMBGhost SMBv3.1.1 RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2020-0796"},
	},
	"RDP": {
		{CVEID: "CVE-2019-0708", Description: "BlueKeep pre-auth RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"},
		{CVEID: "CVE-2019-1181", Description: "DejaBlue pre-auth RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2019-1181"},
	},
	"MySQL": {
		{CVEID: "CVE-2012-2122", Description: "MySQL auth bypass", Severity: "HIGH", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2012-2122"},
		{CVEID: "CVE-2016-6662", Description: "MySQL RCE via config injection", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2016-6662"},
	},
	"Redis": {
		{CVEID: "CVE-2022-0543", Description: "Redis Lua sandbox escape RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"},
	},
	"Elasticsearch": {
		{CVEID: "CVE-2015-1427", Description: "Elasticsearch Groovy sandbox bypass RCE", Severity: "CRITICAL", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-1427"},
	},
	"MongoDB": {
		{CVEID: "INFO-AUTH", Description: "MongoDB exposed without authentication", Severity: "HIGH", Reference: "https://www.mongodb.com/docs/manual/security/"},
	},
	"Docker": {
		{CVEID: "CVE-2019-5736", Description: "runc container escape", Severity: "HIGH", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2019-5736"},
		{CVEID: "INFO-EXPOSED", Description: "Docker API exposed without TLS", Severity: "CRITICAL", Reference: "https://docs.docker.com/engine/security/"},
	},
	"SNMP": {
		{CVEID: "INFO-COMMUNITY", Description: "SNMP default community string", Severity: "MEDIUM", Reference: "https://www.cvedetails.com/cve/CVE-1999-0517"},
	},
	"Telnet": {
		{CVEID: "INFO-CLEARTEXT", Description: "Telnet transmits credentials in cleartext", Severity: "HIGH", Reference: "https://cwe.mitre.org/data/definitions/319.html"},
	},
}

func (SD *ServiceDetector) GrabTCPBanner(Host string, Port int) string {
	Conn, Err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", Host, Port), SD.Timeout)
	if Err != nil {
		return ""
	}
	defer Conn.Close()
	Conn.SetReadDeadline(time.Now().Add(SD.Timeout))
	Scanner := bufio.NewScanner(Conn)
	if Scanner.Scan() {
		return strings.TrimSpace(Scanner.Text())
	}
	return ""
}

func (SD *ServiceDetector) GrabHTTPHeaders(Host string, Port int, TLS bool) (int, map[string]string) {
	Scheme := "http"
	if TLS {
		Scheme = "https"
	}
	Client := &http.Client{
		Timeout: SD.Timeout,
		CheckRedirect: func(Req *http.Request, Via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	Req, Err := http.NewRequest("GET", fmt.Sprintf("%s://%s:%d/", Scheme, Host, Port), nil)
	if Err != nil {
		return 0, nil
	}
	Req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HTONSpider/1.0)")
	Resp, Err := Client.Do(Req)
	if Err != nil {
		return 0, nil
	}
	defer Resp.Body.Close()
	Headers := make(map[string]string)
	for _, H := range []string{"Server", "X-Powered-By", "X-Generator", "X-Frame-Options",
		"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
		"WWW-Authenticate", "X-AspNet-Version"} {
		if V := Resp.Header.Get(H); V != "" {
			Headers[H] = V
		}
	}
	return Resp.StatusCode, Headers
}

func (SD *ServiceDetector) FingerprintService(Banner string, Headers map[string]string, ServiceName string) string {
	BannerLow := strings.ToLower(Banner)
	Parts := []string{}
	Patterns := map[string]string{
		"apache": "Apache", "nginx": "Nginx", "iis": "IIS",
		"openssh": "OpenSSH", "vsftpd": "vsftpd", "proftpd": "ProFTPD",
		"mysql": "MySQL", "postgresql": "PostgreSQL", "redis": "Redis",
		"mongodb": "MongoDB", "memcached": "Memcached",
		"tomcat": "Tomcat", "jetty": "Jetty", "lighttpd": "Lighttpd",
		"microsoft": "Microsoft", "filezilla": "FileZilla",
	}
	for Pattern, Name := range Patterns {
		if strings.Contains(BannerLow, Pattern) {
			Parts = append(Parts, Name)
			break
		}
	}
	if Headers != nil {
		if Server := Headers["Server"]; Server != "" {
			Parts = append(Parts, Server)
		}
		if Powered := Headers["X-Powered-By"]; Powered != "" {
			Parts = append(Parts, "("+Powered+")")
		}
	}
	if len(Parts) == 0 {
		return ServiceName
	}
	return strings.Join(Parts, " ")
}

func (SD *ServiceDetector) DetectPort(Host string, Port int, ServiceName string) ServiceInfo {
	Info := ServiceInfo{Port: Port, Protocol: "tcp", ServiceName: ServiceName, Headers: make(map[string]string)}
	IsHTTP := strings.HasPrefix(ServiceName, "HTTP")
	IsHTTPS := strings.HasPrefix(ServiceName, "HTTPS")

	LogDebugV(fmt.Sprintf("Detecting port %d (%s)", Port, ServiceName))

	if IsHTTP || IsHTTPS {
		Code, Headers := SD.GrabHTTPHeaders(Host, Port, IsHTTPS)
		if Code > 0 {
			Info.Headers = Headers
			Info.Fingerprint = SD.FingerprintService("", Headers, ServiceName)
			Info.Banner = fmt.Sprintf("HTTP %d", Code)
		}
	} else {
		Banner := SD.GrabTCPBanner(Host, Port)
		if Banner != "" {
			Info.Banner = Banner
			Info.Fingerprint = SD.FingerprintService(Banner, nil, ServiceName)
		}
	}

	if Vulns, Ok := VulnDatabase[ServiceName]; Ok {
		Info.Vulns = Vulns
		LogWarn(fmt.Sprintf("Port %d (%s) — %d potential CVE(s)", Port, ServiceName, len(Vulns)))
	}
	return Info
}

func (SD *ServiceDetector) Detect(Target string, OpenPorts []PortResult) ServiceDetectResult {
	Start := time.Now()
	Result := ServiceDetectResult{Target: Target}
	LogInfo(fmt.Sprintf("Service detection — %d open ports to probe", len(OpenPorts)))
	for _, PR := range OpenPorts {
		Info := SD.DetectPort(Target, PR.Port, PR.Service)
		Result.Services = append(Result.Services, Info)
	}
	Result.Elapsed = time.Since(Start)
	LogInfo(fmt.Sprintf("Service detection done in %s", Result.Elapsed.Round(time.Millisecond)))
	return Result
}

func (SD *ServiceDetector) RenderTable(Result ServiceDetectResult) string {
	var B strings.Builder
	W := TermWidth()
	Sep := strings.Repeat("-", W)

	B.WriteString(fmt.Sprintf("\n%s\n", Sep))
	B.WriteString(fmt.Sprintf("  TARGET  : %s\n", Result.Target))
	B.WriteString(fmt.Sprintf("  ELAPSED : %s\n", Result.Elapsed.Round(time.Millisecond)))
	B.WriteString(fmt.Sprintf("%s\n", Sep))

	for _, Svc := range Result.Services {
		B.WriteString(fmt.Sprintf("  PORT     : %d/tcp\n", Svc.Port))
		B.WriteString(fmt.Sprintf("  SERVICE  : %s\n", Svc.ServiceName))
		if Svc.Fingerprint != "" && Svc.Fingerprint != Svc.ServiceName {
			B.WriteString(fmt.Sprintf("  VERSION  : %s\n", Svc.Fingerprint))
		}
		if Svc.Banner != "" {
			B.WriteString(fmt.Sprintf("  BANNER   : %s\n", Svc.Banner))
		}
		if len(Svc.Headers) > 0 {
			B.WriteString("  HEADERS  :\n")
			for K, V := range Svc.Headers {
				B.WriteString(fmt.Sprintf("    %-35s %s\n", K+":", V))
			}
		}
		if len(Svc.Vulns) > 0 {
			B.WriteString("  VULNS    :\n")
			for _, V := range Svc.Vulns {
				B.WriteString(fmt.Sprintf("    [%s] %s - %s\n", V.Severity, V.CVEID, V.Description))
			}
		}
		B.WriteString(fmt.Sprintf("%s\n", Sep))
	}
	return B.String()
}
