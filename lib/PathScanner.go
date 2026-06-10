package lib

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PathResult struct {
	Path       string
	StatusCode int
	Size       int64
	Redirect   string
	Sensitive  bool
}

type PathScanResult struct {
	Target  string
	Found   []PathResult
	Elapsed time.Duration
	Tried   int
}

type PathScanner struct {
	Timeout     time.Duration
	Concurrency int
	UserAgent   string
	Paths       []string
}

var SensitivePaths = []string{
	"/.env", "/.env.local", "/.env.development", "/.env.production", "/.env.backup",
	"/.git", "/.git/config", "/.git/HEAD", "/.git/index", "/.git/COMMIT_EDITMSG",
	"/.svn", "/.svn/entries", "/.svn/wc.db",
	"/.htaccess", "/.htpasswd", "/.htpasswd.bak",
	"/config.php", "/config.php.bak", "/config.php.old", "/configuration.php",
	"/wp-config.php", "/wp-config.php.bak", "/wp-config.old",
	"/config.yml", "/config.yaml", "/config.json", "/config.xml",
	"/database.yml", "/database.php", "/db.php", "/db.sql",
	"/settings.py", "/settings.php", "/settings.json",
	"/local_settings.py", "/local.py",
	"/secrets.json", "/secrets.yml", "/secrets.php",
	"/credentials.json", "/credentials.yml",
	"/id_rsa", "/id_rsa.pub", "/id_dsa", "/.ssh/id_rsa", "/.ssh/config",
	"/backup.sql", "/backup.zip", "/backup.tar.gz", "/backup.tgz",
	"/dump.sql", "/database.sql", "/db_backup.sql",
	"/admin", "/admin/", "/admin/login", "/admin/index.php",
	"/administrator", "/administrator/index.php",
	"/wp-admin", "/wp-admin/", "/wp-login.php",
	"/phpmyadmin", "/phpmyadmin/", "/pma/", "/myadmin/",
	"/adminer.php", "/adminer/",
	"/panel", "/panel/", "/control", "/cpanel", "/webadmin",
	"/manager", "/manager/html", "/management",
	"/api", "/api/v1", "/api/v2", "/api/v3", "/api/swagger",
	"/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/swagger.yaml",
	"/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs.json",
	"/graphql", "/graphiql",
	"/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
	"/actuator/mappings", "/actuator/metrics", "/actuator/logfile",
	"/metrics", "/health", "/health/", "/status", "/status/",
	"/info", "/env", "/debug", "/trace",
	"/console", "/h2-console", "/jolokia",
	"/.well-known", "/.well-known/security.txt",
	"/robots.txt", "/sitemap.xml", "/sitemap.xml.gz",
	"/crossdomain.xml", "/clientaccesspolicy.xml",
	"/phpinfo.php", "/info.php", "/php.php", "/test.php",
	"/server-status", "/server-info",
	"/nginx_status", "/stub_status",
	"/trace.axd", "/elmah.axd", "/WebResource.axd",
	"/login", "/login.php", "/login.html", "/signin", "/signup",
	"/register", "/forgot-password", "/reset-password",
	"/uploads", "/upload", "/files", "/static", "/assets",
	"/public", "/private", "/temp", "/tmp",
	"/logs", "/log", "/error.log", "/access.log", "/debug.log",
	"/application.log", "/app.log",
	"/.DS_Store", "/Thumbs.db", "/desktop.ini",
	"/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
	"/yarn.lock", "/Gemfile", "/Gemfile.lock", "/requirements.txt",
	"/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
	"/Makefile", "/Vagrantfile", "/terraform.tfstate",
	"/.travis.yml", "/.gitlab-ci.yml", "/.github", "/Jenkinsfile",
	"/cgi-bin", "/cgi-bin/", "/cgi-bin/admin.cgi",
	"/shell.php", "/cmd.php", "/backdoor.php", "/webshell.php",
	"/c99.php", "/r57.php", "/b374k.php",
	"/.bash_history", "/.bash_profile", "/.bashrc", "/.profile",
	"/etc/passwd", "/etc/shadow", "/etc/hosts", "/proc/self/environ",
	"/old", "/bak", "/backup", "/new", "/dev", "/test",
	"/xmlrpc.php", "/feed", "/feed/", "/rss", "/rss.xml",
}

var HighSensitivity = map[string]bool{
	"/.env": true, "/.git/config": true, "/.htpasswd": true,
	"/wp-config.php": true, "/config.php": true, "/id_rsa": true,
	"/database.sql": true, "/backup.sql": true, "/dump.sql": true,
	"/secrets.json": true, "/credentials.json": true,
	"/phpinfo.php": true, "/server-status": true,
	"/actuator/env": true, "/actuator/beans": true,
	"/.bash_history": true, "/etc/passwd": true,
}

func NewPathScanner(TimeoutSec int, Concurrency int, CustomPaths []string) *PathScanner {
	Paths := CustomPaths
	if len(Paths) == 0 {
		Paths = SensitivePaths
	}
	return &PathScanner{
		Timeout:     time.Duration(TimeoutSec) * time.Second,
		Concurrency: Concurrency,
		UserAgent:   "Mozilla/5.0 (compatible; HTONSpider/1.0)",
		Paths:       Paths,
	}
}

func (P *PathScanner) CheckPath(BaseURL, Path string) PathResult {
	Result := PathResult{Path: Path}
	Client := &http.Client{
		Timeout: P.Timeout,
		CheckRedirect: func(Req *http.Request, Via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	URL := strings.TrimRight(BaseURL, "/") + Path
	Req, Err := http.NewRequest("GET", URL, nil)
	if Err != nil {
		return Result
	}
	Req.Header.Set("User-Agent", P.UserAgent)
	Resp, Err := Client.Do(Req)
	if Err != nil {
		return Result
	}
	defer Resp.Body.Close()
	Result.StatusCode = Resp.StatusCode
	Result.Size = Resp.ContentLength
	if Resp.StatusCode >= 300 && Resp.StatusCode < 400 {
		Result.Redirect = Resp.Header.Get("Location")
	}
	if _, Ok := HighSensitivity[Path]; Ok {
		Result.Sensitive = true
	}
	return Result
}

func (P *PathScanner) Scan(Target string) PathScanResult {
	Start := time.Now()
	BaseURL := Target
	if !strings.HasPrefix(BaseURL, "http") {
		BaseURL = "http://" + BaseURL
	}
	ScanRes := PathScanResult{Target: Target, Tried: len(P.Paths)}
	Sem := make(chan struct{}, P.Concurrency)
	Mu := &sync.Mutex{}
	Wg := &sync.WaitGroup{}
	var Counter int64

	LogInfo(fmt.Sprintf("Path scan on %s — %d paths, threads: %d", Target, len(P.Paths), P.Concurrency))

	for _, Path := range P.Paths {
		Wg.Add(1)
		Sem <- struct{}{}
		go func(Pt string) {
			defer Wg.Done()
			defer func() { <-Sem }()
			Res := P.CheckPath(BaseURL, Pt)
			Done := atomic.AddInt64(&Counter, 1)
			if Done%50 == 0 {
				LogDebugV(fmt.Sprintf("Progress %d/%d paths probed", Done, int64(len(P.Paths))))
			}
			if Res.StatusCode > 0 && Res.StatusCode != 404 && Res.StatusCode != 400 {
				Note := ""
				if Res.Sensitive {
					Note = " [!]"
				}
				LogSuccess(fmt.Sprintf("[%d] %s%s", Res.StatusCode, Pt, Note))
				Mu.Lock()
				ScanRes.Found = append(ScanRes.Found, Res)
				Mu.Unlock()
			}
		}(Path)
	}

	Wg.Wait()
	ScanRes.Elapsed = time.Since(Start)
	LogInfo(fmt.Sprintf("Path scan done — %d found in %s", len(ScanRes.Found), ScanRes.Elapsed.Round(time.Millisecond)))
	return ScanRes
}

func (P *PathScanner) RenderTable(Result PathScanResult) string {
	var B strings.Builder
	W := TermWidth()
	Sep := strings.Repeat("-", W)

	Headers := []string{"STATUS", "PATH", "SIZE", "NOTE"}
	var Rows [][]string
	for _, PR := range Result.Found {
		Note := ""
		if PR.Sensitive {
			Note = "[!] HIGH SENSITIVITY"
		}
		if PR.Redirect != "" {
			Note = "-> " + PR.Redirect
		}
		Size := fmt.Sprintf("%d", PR.Size)
		if PR.Size == -1 {
			Size = "-"
		}
		Rows = append(Rows, []string{fmt.Sprintf("%d", PR.StatusCode), PR.Path, Size, Note})
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
