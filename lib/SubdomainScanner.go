package lib

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SubdomainResult struct {
	Subdomain string
	IP        []string
	Active    bool
}

type SubdomainScanResult struct {
	Target  string
	Found   []SubdomainResult
	Elapsed time.Duration
	Tried   int
}

type SubdomainScanner struct {
	Timeout     time.Duration
	Concurrency int
	Wordlist    []string
}

var DefaultWordlist = []string{
	"www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
	"api", "api2", "api3", "dev", "staging", "stage", "test", "testing",
	"prod", "production", "beta", "alpha", "demo", "sandbox",
	"admin", "administrator", "manage", "manager", "panel", "cpanel",
	"dashboard", "portal", "control", "console",
	"app", "app1", "app2", "apps", "application",
	"blog", "cms", "shop", "store", "forum", "wiki", "docs", "help",
	"support", "ticket", "helpdesk", "kb", "knowledge",
	"static", "cdn", "assets", "media", "img", "images", "files",
	"download", "downloads", "upload", "uploads", "s3", "storage",
	"ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
	"mx", "mx1", "mx2", "relay", "gateway",
	"vpn", "remote", "ssh", "sftp", "git", "svn", "repo",
	"db", "database", "mysql", "pgsql", "mongo", "redis", "elastic",
	"ci", "cd", "jenkins", "gitlab", "github", "jira", "confluence",
	"monitor", "status", "health", "metrics", "grafana", "kibana",
	"proxy", "lb", "loadbalancer", "balancer", "nginx", "apache",
	"mobile", "m", "wap", "touch",
	"secure", "ssl", "auth", "login", "sso", "oauth",
	"internal", "intranet", "private", "corp", "corporate",
	"cloud", "aws", "azure", "gcp",
	"v1", "v2", "v3", "new", "old", "legacy", "backup",
	"web", "web1", "web2", "web3", "node", "node1", "node2",
	"server", "server1", "server2", "host", "host1",
	"img", "css", "js", "assets", "public",
	"exchange", "autodiscover", "autoconfig", "owa",
	"meet", "video", "stream", "live",
	"crm", "erp", "hr", "payroll", "billing", "invoice",
	"search", "query", "index", "sitemap",
	"us", "eu", "asia", "ap",
	"office", "remote", "work",
}

var DnsResolverPool = &net.Resolver{
	PreferGo: true,
	Dial: func(Ctx context.Context, Network, Address string) (net.Conn, error) {
		D := net.Dialer{Timeout: 3 * time.Second}
		return D.DialContext(Ctx, "udp", "8.8.8.8:53")
	},
}

func NewSubdomainScanner(TimeoutSec int, Concurrency int, Wordlist []string) *SubdomainScanner {
	WL := Wordlist
	if len(WL) == 0 {
		WL = DefaultWordlist
	}
	if Concurrency < 1 {
		Concurrency = 1
	}
	if Concurrency > 100 {
		Concurrency = 100
	}
	return &SubdomainScanner{
		Timeout:     time.Duration(TimeoutSec) * time.Second,
		Concurrency: Concurrency,
		Wordlist:    WL,
	}
}

func (S *SubdomainScanner) CheckSubdomain(Subdomain string) SubdomainResult {
	Result := SubdomainResult{Subdomain: Subdomain}
	Ctx, Cancel := context.WithTimeout(context.Background(), S.Timeout)
	defer Cancel()
	Addrs, Err := DnsResolverPool.LookupHost(Ctx, Subdomain)
	if Err == nil && len(Addrs) > 0 {
		Result.Active = true
		Result.IP = Addrs
	}
	return Result
}

func (S *SubdomainScanner) Scan(Target string) SubdomainScanResult {
	Start := time.Now()
	ScanRes := SubdomainScanResult{Target: Target, Tried: len(S.Wordlist)}

	Sem := make(chan struct{}, S.Concurrency)
	Mu := &sync.Mutex{}
	Wg := &sync.WaitGroup{}
	var Counter int64

	LogInfo(fmt.Sprintf("Subdomain scan on %s — %d words, threads: %d, timeout: %s",
		Target, len(S.Wordlist), S.Concurrency, S.Timeout))

	for _, Word := range S.Wordlist {
		Wg.Add(1)
		Sem <- struct{}{}
		go func(W string) {
			defer Wg.Done()
			defer func() { <-Sem }()
			Full := fmt.Sprintf("%s.%s", W, Target)
			Res := S.CheckSubdomain(Full)
			Done := atomic.AddInt64(&Counter, 1)
			if Done%20 == 0 {
				Mu.Lock()
				Found := len(ScanRes.Found)
				Mu.Unlock()
				LogDebugV(fmt.Sprintf("Progress %d/%d — %d found", Done, int64(len(S.Wordlist)), int64(Found)))
			}
			if Res.Active {
				LogSuccess(fmt.Sprintf("Found: %s -> %s", Full, strings.Join(Res.IP, ", ")))
				Mu.Lock()
				ScanRes.Found = append(ScanRes.Found, Res)
				Mu.Unlock()
			}
		}(Word)
	}

	Wg.Wait()
	ScanRes.Elapsed = time.Since(Start)
	LogInfo(fmt.Sprintf("Subdomain scan done — %d/%d found in %s",
		len(ScanRes.Found), len(S.Wordlist), ScanRes.Elapsed.Round(time.Millisecond)))
	return ScanRes
}

func (S *SubdomainScanner) RenderTable(Result SubdomainScanResult) string {
	var B strings.Builder
	W := TermWidth()
	Sep := strings.Repeat("-", W)

	Headers := []string{"SUBDOMAIN", "IP(s)"}
	var Rows [][]string
	for _, SR := range Result.Found {
		Rows = append(Rows, []string{SR.Subdomain, strings.Join(SR.IP, ", ")})
	}
	Widths := CalcColWidths(Headers, Rows, W-2)

	B.WriteString(fmt.Sprintf("\n%s\n", Sep))
	B.WriteString(fmt.Sprintf("  TARGET  : %s\n", Result.Target))
	B.WriteString(fmt.Sprintf("  FOUND   : %d / %d\n", len(Result.Found), Result.Tried))
	B.WriteString(fmt.Sprintf("  ELAPSED : %s\n", Result.Elapsed.Round(time.Millisecond)))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	B.WriteString(TableRow(Headers, Widths))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	for _, Row := range Rows {
		B.WriteString(TableRow(Row, Widths))
	}
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	return B.String()
}
