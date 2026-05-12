#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>
#include <signal.h>
#include <math.h>
#include <stdarg.h>
#include <ifaddrs.h>

#define MaxProxies      65536
#define DefaultPort     1080
#define DefaultTimeout  3
#define DefaultThreads  200
#define DefaultExport   "checked.txt"
#define VersionString   "3.0.0"
#define TestHost        "google.com"
#define TestPort        80
#define Socks4Ver       0x04
#define Socks5Ver       0x05
#define PingCount       4
#define MaxPorts        1024
#define DnsTimeout      5
#define TraceMaxHops    30

typedef enum { ProtoHTTP=0, ProtoSocks4=1, ProtoSocks5=2, ProtoAuto=3 }  ProxyProto;
typedef enum { StatusUnknown=0, StatusAlive=1, StatusDead=2 }             ProxyStatus;
typedef enum { FilterNone=0, FilterAlive=1, FilterDead=2 }                FilterMode;

typedef struct {
    char        Host[256];
    int         Port;
    ProxyStatus Status;
    ProxyProto  Proto;
    long        Latency;
} ProxyEntry;

typedef struct {
    ProxyEntry      *Entries;
    int              Count;
    int              Capacity;
    pthread_mutex_t  Lock;
} ProxyList;

typedef struct {
    ProxyList  *List;
    int         Index;
    int         Timeout;
    ProxyProto  Proto;
} WorkerArgs;

typedef struct {
    char  Source[256];
    char  ExportFile[256];
    char  LoadFile[256];
    int   Port;
    int   Timeout;
    int   Threads;
    int   ExportEnabled;
    int   HelpRequested;
    int   HasLoadFile;
    int   HasSource;
    int   Verbose;
    FilterMode  Filter;
    ProxyProto  Proto;
} ProxyConfig;

typedef struct {
    int  Open;
    int  Closed;
    int  Filtered;
    long Latency;
    char Service[32];
    char Banner[256];
} PortResult;

typedef struct {
    char  Hop[64];
    char  Hostname[256];
    long  RttMs;
    int   Reached;
} TraceHop;

static ProxyList        GlobalList;
static ProxyConfig      GlobalPCfg;
static volatile int     DoneCount  = 0;
static volatile int     AliveCount = 0;
static volatile int     DeadCount  = 0;
static volatile int     Running    = 1;
static pthread_mutex_t  DoneLock   = PTHREAD_MUTEX_INITIALIZER;
static time_t           StartTime;

static const char *CR   = "\033[0m";
static const char *C51  = "\033[38;5;51m";
static const char *C82  = "\033[38;5;82m";
static const char *C196 = "\033[38;5;196m";
static const char *C226 = "\033[38;5;226m";
static const char *C201 = "\033[38;5;201m";
static const char *C255 = "\033[38;5;255m";
static const char *C245 = "\033[38;5;245m";
static const char *C214 = "\033[38;5;214m";
static const char *C99  = "\033[38;5;99m";
static const char *C87  = "\033[38;5;87m";
static const char *C39  = "\033[38;5;39m";
static const char *C46  = "\033[38;5;46m";
static const char *C208 = "\033[38;5;208m";
static const char *BD   = "\033[1m";

static void SigHandler(int S) { (void)S; Running = 0; }

static long GetMs() {
    struct timeval T;
    gettimeofday(&T, NULL);
    return (long)(T.tv_sec * 1000 + T.tv_usec / 1000);
}

static void Ruler(int W, const char *Col) {
    printf("  %s%s", Col ? Col : C245, BD);
    for (int i = 0; i < W; i++) printf("─");
    printf("%s\n", CR);
}

static void PrintBanner() {
    printf("\n");
    printf("%s%s", C51, BD);
    printf("  ██╗  ██╗████████╗ ██████╗ ███╗   ██╗\n");
    printf("  ██║  ██║╚══██╔══╝██╔═══██╗████╗  ██║\n");
    printf("  ███████║   ██║   ██║   ██║██╔██╗ ██║\n");
    printf("  ██╔══██║   ██║   ██║   ██║██║╚██╗██║\n");
    printf("  ██║  ██║   ██║   ╚██████╔╝██║ ╚████║\n");
    printf("  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝\n");
    printf("%s", CR);
    printf("  %s%sSPIDER%s  %s%sNetwork Intelligence Toolkit  ·  v%s%s\n",
        C245, BD, CR, C245, BD, VersionString, CR);
    printf("  %s%s────────────────────────────────────────────────%s\n\n", C245, BD, CR);
}

static void PrintMainHelp(const char *P) {
    PrintBanner();
    printf("  %s%sUSAGE%s\n  %s%s%s <module> [options]%s\n\n", BD, C255, CR, BD, C51, P, CR);

    printf("  %s%sMODULES%s\n", BD, C245, CR);
    printf("  %s%sproxy%s      %s%-14s%s  Multi-protocol proxy checker (HTTP/SOCKS4/SOCKS5)\n",  BD, C51,  CR, BD, "", CR);
    printf("  %s%sscan%s       %s%-14s%s  TCP/UDP port scanner with banner grabbing\n",           BD, C226, CR, BD, "", CR);
    printf("  %s%sping%s       %s%-14s%s  ICMP/TCP ping with RTT statistics\n",                   BD, C82,  CR, BD, "", CR);
    printf("  %s%strace%s      %s%-14s%s  Traceroute with hostname resolution\n",                 BD, C201, CR, BD, "", CR);
    printf("  %s%sdns%s        %s%-14s%s  Full DNS record lookup (A/AAAA/MX/NS/TXT/CNAME/SOA)\n", BD, C214, CR, BD, "", CR);
    printf("  %s%swhois%s      %s%-14s%s  WHOIS query for IP/domain\n",                           BD, C87,  CR, BD, "", CR);
    printf("  %s%shttp%s       %s%-14s%s  HTTP/HTTPS header inspector & response analyzer\n",     BD, C39,  CR, BD, "", CR);
    printf("  %s%sifinfo%s     %s%-14s%s  Local network interface information\n",                 BD, C99,  CR, BD, "", CR);
    printf("  %s%sbanner%s     %s%-14s%s  Raw TCP/UDP banner grabber\n",                          BD, C46,  CR, BD, "", CR);
    printf("  %s%ssubnet%s     %s%-14s%s  Subnet calculator and IP range info\n",                 BD, C208, CR, BD, "", CR);
    printf("\n  %s%s%s <module> -h  for module-specific help%s\n\n", C245, BD, P, CR);
}


static int ResolveToAddr(const char *Host, struct sockaddr_in *Out) {
    struct addrinfo Hints, *Res;
    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family = AF_INET;
    if (getaddrinfo(Host, NULL, &Hints, &Res) != 0) return -1;
    *Out = *(struct sockaddr_in *)Res->ai_addr;
    freeaddrinfo(Res);
    return 0;
}

static int ResolveStr(const char *Host, char *OutIP, size_t Len) {
    struct sockaddr_in SA;
    if (ResolveToAddr(Host, &SA) < 0) return -1;
    inet_ntop(AF_INET, &SA.sin_addr, OutIP, (socklen_t)Len);
    return 0;
}

static int ReverseResolve(const char *IP, char *OutHost, size_t Len) {
    struct sockaddr_in SA;
    memset(&SA, 0, sizeof(SA));
    SA.sin_family = AF_INET;
    inet_pton(AF_INET, IP, &SA.sin_addr);
    return getnameinfo((struct sockaddr *)&SA, sizeof(SA), OutHost, (socklen_t)Len, NULL, 0, 0);
}

static const char *KnownService(int Port) {
    switch (Port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 143:  return "IMAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 1080: return "SOCKS";
        case 1433: return "MSSQL";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        case 27017:return "MongoDB";
        default:   return "";
    }
}

static int TcpConnect(const char *Host, int Port, int Tsec, long *OutLat) {
    struct addrinfo Hints, *Res = NULL;
    char PS[16];
    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family   = AF_UNSPEC;
    Hints.ai_socktype = SOCK_STREAM;
    snprintf(PS, sizeof(PS), "%d", Port);
    if (getaddrinfo(Host, PS, &Hints, &Res) != 0) return -1;

    int Fd = socket(Res->ai_family, Res->ai_socktype, Res->ai_protocol);
    if (Fd < 0) { freeaddrinfo(Res); return -1; }

    fcntl(Fd, F_SETFL, fcntl(Fd, F_GETFL, 0) | O_NONBLOCK);
    long T0 = GetMs();
    connect(Fd, Res->ai_addr, Res->ai_addrlen);
    freeaddrinfo(Res);

    fd_set W; struct timeval Tv = { Tsec, 0 };
    FD_ZERO(&W); FD_SET(Fd, &W);
    if (select(Fd + 1, NULL, &W, NULL, &Tv) <= 0) { close(Fd); return -1; }

    int E = 0; socklen_t L = sizeof(E);
    getsockopt(Fd, SOL_SOCKET, SO_ERROR, &E, &L);
    if (E != 0) { close(Fd); return -1; }

    if (OutLat) *OutLat = GetMs() - T0;
    return Fd;
}

static int SendAll(int Fd, const unsigned char *B, int L) {
    int S = 0;
    while (S < L) { int N = (int)send(Fd, B + S, L - S, 0); if (N <= 0) return -1; S += N; }
    return 0;
}

static int RecvExact(int Fd, unsigned char *B, int L, int Tsec) {
    int G = 0;
    while (G < L) {
        fd_set R; struct timeval Tv = { Tsec, 0 };
        FD_ZERO(&R); FD_SET(Fd, &R);
        if (select(Fd + 1, &R, NULL, NULL, &Tv) <= 0) return -1;
        int N = (int)recv(Fd, B + G, L - G, 0);
        if (N <= 0) return -1;
        G += N;
    }
    return 0;
}

static int ProbeSocks5(int Fd, int Ts) {
    unsigned char H[3] = { Socks5Ver, 0x01, 0x00 };
    if (SendAll(Fd, H, 3) < 0) return 0;
    unsigned char HR[2];
    if (RecvExact(Fd, HR, 2, Ts) < 0) return 0;
    if (HR[0] != Socks5Ver || HR[1] != 0x00) return 0;
    size_t HL = strlen(TestHost);
    unsigned char Rq[300]; int I = 0;
    Rq[I++]=Socks5Ver; Rq[I++]=0x01; Rq[I++]=0x00; Rq[I++]=0x03;
    Rq[I++]=(unsigned char)HL;
    memcpy(&Rq[I], TestHost, HL); I += (int)HL;
    Rq[I++]=(TestPort>>8)&0xFF; Rq[I++]=TestPort&0xFF;
    if (SendAll(Fd, Rq, I) < 0) return 0;
    unsigned char ConnResp[10];
    if (RecvExact(Fd, ConnResp, 10, Ts) < 0) return 0;
    return (ConnResp[0]==Socks5Ver && ConnResp[1]==0x00) ? 1 : 0;
}

static int ProbeSocks4(int Fd, int Ts) {
    struct addrinfo Hints, *Res;
    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family = AF_INET;
    if (getaddrinfo(TestHost, NULL, &Hints, &Res) != 0) return 0;
    struct in_addr Tgt = ((struct sockaddr_in*)Res->ai_addr)->sin_addr;
    freeaddrinfo(Res);
    unsigned char Rq[9];
    Rq[0]=Socks4Ver; Rq[1]=0x01;
    Rq[2]=(TestPort>>8)&0xFF; Rq[3]=TestPort&0xFF;
    memcpy(&Rq[4], &Tgt.s_addr, 4); Rq[8]=0x00;
    if (SendAll(Fd, Rq, 9) < 0) return 0;
    unsigned char Rs[8];
    if (RecvExact(Fd, Rs, 8, Ts) < 0) return 0;
    return (Rs[0]==0x00 && Rs[1]==0x5A) ? 1 : 0;
}

static int ProbeHTTP(int Fd, int Ts) {
    char Rq[512];
    snprintf(Rq, sizeof(Rq),
        "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
        TestHost, TestPort, TestHost, TestPort);
    if (SendAll(Fd, (unsigned char*)Rq, (int)strlen(Rq)) < 0) return 0;
    unsigned char Rs[256]; memset(Rs, 0, sizeof(Rs));
    fd_set R; struct timeval Tv = { Ts, 0 };
    FD_ZERO(&R); FD_SET(Fd, &R);
    if (select(Fd + 1, &R, NULL, NULL, &Tv) <= 0) return 0;
    int N = (int)recv(Fd, Rs, sizeof(Rs)-1, 0);
    if (N < 8) return 0;
    return (strstr((char*)Rs, "200") || strstr((char*)Rs, "HTTP")) ? 1 : 0;
}

static ProxyStatus RunProxyCheck(const char *Host, int Port, int Ts,
                                  long *OL, ProxyProto In, ProxyProto *Out) {
    long Lat = 0;
    if (In != ProtoAuto) {
        int Fd = TcpConnect(Host, Port, Ts, &Lat);
        if (Fd < 0) return StatusDead;
        int Ok = 0;
        switch (In) {
            case ProtoSocks5: Ok = ProbeSocks5(Fd, Ts); break;
            case ProtoSocks4: Ok = ProbeSocks4(Fd, Ts); break;
            default:          Ok = ProbeHTTP(Fd, Ts);   break;
        }
        close(Fd);
        if (Ok) { if (OL) *OL = Lat; if (Out) *Out = In; }
        return Ok ? StatusAlive : StatusDead;
    }

    int Fd = TcpConnect(Host, Port, Ts, &Lat);
    if (Fd < 0) return StatusDead;
    if (ProbeSocks5(Fd, Ts)) {
        close(Fd);
        if (OL) *OL = Lat;
        if (Out) *Out = ProtoSocks5;
        return StatusAlive;
    }
    shutdown(Fd, SHUT_RDWR); close(Fd);

    Fd = TcpConnect(Host, Port, Ts, &Lat);
    if (Fd < 0) return StatusDead;
    if (ProbeSocks4(Fd, Ts)) {
        close(Fd);
        if (OL) *OL = Lat;
        if (Out) *Out = ProtoSocks4;
        return StatusAlive;
    }
    shutdown(Fd, SHUT_RDWR); close(Fd);

    Fd = TcpConnect(Host, Port, Ts, &Lat);
    if (Fd < 0) return StatusDead;
    if (ProbeHTTP(Fd, Ts)) {
        close(Fd);
        if (OL) *OL = Lat;
        if (Out) *Out = ProtoHTTP;
        return StatusAlive;
    }
    close(Fd);
    return StatusDead;
}

static void *ProxyWorker(void *Arg) {
    WorkerArgs *WA = (WorkerArgs*)Arg;
    ProxyEntry *E  = &WA->List->Entries[WA->Index];
    long Lat = 0; ProxyProto Det = WA->Proto;
    E->Status  = RunProxyCheck(E->Host, E->Port, WA->Timeout, &Lat, WA->Proto, &Det);
    E->Latency = Lat;
    E->Proto   = (E->Status == StatusAlive) ? Det : WA->Proto;
    pthread_mutex_lock(&DoneLock);
    DoneCount++;
    if (E->Status == StatusAlive) AliveCount++; else DeadCount++;
    pthread_mutex_unlock(&DoneLock);
    free(WA);
    return NULL;
}

static void ParseHostPort(const char *In, char *OH, int *OP, int Def) {
    const char *C = strrchr(In, ':');
    if (C) {
        size_t L = (size_t)(C - In); if (L >= 256) L = 255;
        strncpy(OH, In, L); OH[L] = '\0';
        *OP = atoi(C + 1);
        if (*OP <= 0 || *OP > 65535) *OP = Def;
    } else {
        strncpy(OH, In, 255); OH[255] = '\0'; *OP = Def;
    }
}

static void TrimLine(char *S) {
    size_t L = strlen(S);
    while (L > 0 && (S[L-1]=='\n'||S[L-1]=='\r'||S[L-1]==' ')) S[--L] = '\0';
    char *P = S; while (*P && (*P==' '||*P=='\t')) P++;
    if (P != S) memmove(S, P, strlen(P)+1);
}

static void InitProxyList(ProxyList *PL) {
    PL->Entries  = (ProxyEntry*)malloc(sizeof(ProxyEntry) * MaxProxies);
    PL->Count    = 0;
    PL->Capacity = MaxProxies;
    pthread_mutex_init(&PL->Lock, NULL);
}

static void FreeProxyList(ProxyList *PL) {
    free(PL->Entries);
    pthread_mutex_destroy(&PL->Lock);
}

static void AddProxy(ProxyList *PL, const char *H, int P, ProxyProto Pr) {
    pthread_mutex_lock(&PL->Lock);
    if (PL->Count < PL->Capacity) {
        ProxyEntry *E = &PL->Entries[PL->Count++];
        strncpy(E->Host, H, 255); E->Host[255]='\0';
        E->Port=P; E->Status=StatusUnknown; E->Proto=Pr; E->Latency=0;
    }
    pthread_mutex_unlock(&PL->Lock);
}

static void LoadProxiesFromFile(ProxyList *PL, const char *Fn, int Def, ProxyProto Pr) {
    FILE *Fp = fopen(Fn, "r");
    if (!Fp) { fprintf(stderr, "  %s%s[ERR]%s Cannot open: %s\n\n", BD, C196, CR, Fn); exit(1); }
    char Line[512]; int N = 0;
    while (fgets(Line, sizeof(Line), Fp)) {
        TrimLine(Line);
        if (!Line[0] || Line[0]=='#') continue;
        char H[256]; int P;
        ParseHostPort(Line, H, &P, Def);
        AddProxy(PL, H, P, Pr);
        N++;
    }
    fclose(Fp);
    printf("  %s%s[+]%s Loaded %s%s%d%s entr%s from %s%s%s%s\n",
        BD, C82, CR, BD, C255, N, CR, N==1?"y":"ies", BD, C87, Fn, CR);
}

static const char *ProtoTag(ProxyProto P) {
    switch (P) {
        case ProtoHTTP:   return "HTTP  ";
        case ProtoSocks4: return "SOCKS4";
        case ProtoSocks5: return "SOCKS5";
        default:          return "AUTO  ";
    }
}

static const char *ProtoCol(ProxyProto P) {
    switch (P) {
        case ProtoHTTP:   return "\033[38;5;39m";
        case ProtoSocks4: return "\033[38;5;201m";
        case ProtoSocks5: return "\033[38;5;226m";
        default:          return "\033[38;5;245m";
    }
}

static const char *LatCol(long Ms) {
    if (Ms < 300)  return "\033[38;5;82m";
    if (Ms < 800)  return "\033[38;5;226m";
    if (Ms < 2000) return "\033[38;5;214m";
    return "\033[38;5;196m";
}

static void DrawProxyProgress(int Done, int Total, int Alive, int Dead, int Active) {
    int BW = 28, Filled = (Total>0) ? (Done*BW/Total) : 0;
    float Pct = (Total>0) ? ((float)Done*100.0f/(float)Total) : 0.0f;
    time_t El = time(NULL) - StartTime;
    int Rem = 0;
    if (Done > 0 && El > 0) { float R = (float)Done/(float)El; Rem = (R>0.0f) ? (int)((Total-Done)/R) : 0; }
    printf("\r  %s%s[%s", BD, C245, CR);
    for (int i = 0; i < BW; i++) printf(i<Filled ? "%s%s█%s" : "%s▒%s", (i<Filled?BD:""), C51, CR);
    printf("%s%s]%s %s%s%5.1f%%%s  %s%s%d/%d%s  %s%s+%d%s  %s%s-%d%s  %s%s~%ds%s  %s%s[%dT]%s",
        BD, C245, CR, BD, C255, Pct, CR,
        C245, BD, Done, Total, CR,
        C82, BD, Alive, CR,
        C196, BD, Dead, CR,
        C214, BD, Rem, CR,
        C99, BD, Active, CR);
    fflush(stdout);
}

static void RunProxyChecks(ProxyList *PL, int Ts, int MaxT, ProxyProto Proto) {
    int Total=PL->Count, Active=0, Launched=0;
    StartTime = time(NULL);
    printf("\n  %s%s[*]%s %s%s%d%s proxies  %sproto:%s %s%s%s%s  %sthreads:%s %s%s%d%s  %stimeout:%s %s%s%ds%s\n\n",
        BD, C51, CR, BD, C255, Total, CR,
        C245, CR, BD, ProtoCol(Proto), ProtoTag(Proto), CR,
        C245, CR, BD, C201, MaxT, CR,
        C245, CR, BD, C214, Ts, CR);
    pthread_t *Threads = (pthread_t*)malloc(sizeof(pthread_t)*Total);
    while (Running && (Launched < Total || Active > 0)) {
        while (Active < MaxT && Launched < Total && Running) {
            WorkerArgs *WA = (WorkerArgs*)malloc(sizeof(WorkerArgs));
            WA->List=PL; WA->Index=Launched; WA->Timeout=Ts; WA->Proto=Proto;
            pthread_create(&Threads[Launched], NULL, ProxyWorker, WA);
            Launched++; Active++;
        }
        usleep(5000);
        pthread_mutex_lock(&DoneLock);
        int D=DoneCount, A=AliveCount, X=DeadCount;
        pthread_mutex_unlock(&DoneLock);
        Active = Launched - D;
        DrawProxyProgress(D, Total, A, X, Active);
    }
    for (int i = 0; i < Launched; i++) pthread_join(Threads[i], NULL);
    free(Threads);
    DrawProxyProgress(Total, Total, AliveCount, DeadCount, 0);
    printf("\n");
}

static void PrintProxyResults(ProxyList *PL, FilterMode Filter, int Verbose) {
    printf("\n"); Ruler(62, C245);
    printf("  %s%s  PROXY RESULTS%s\n", BD, C255, CR);
    Ruler(62, C245); printf("\n");
    int Shown = 0;
    for (int i = 0; i < PL->Count; i++) {
        ProxyEntry *E = &PL->Entries[i];
        if (Filter==FilterAlive && E->Status!=StatusAlive) continue;
        if (Filter==FilterDead  && E->Status!=StatusDead)  continue;
        if (E->Status == StatusAlive) {
            char Addr[300]; snprintf(Addr, sizeof(Addr), "%s:%d", E->Host, E->Port);
            printf("  %s%s ALIVE %s  %s%s%s%-6s%s  %s%s%-42s%s",
                BD, C82, CR, BD, ProtoCol(E->Proto), BD, ProtoTag(E->Proto), CR,
                BD, C255, Addr, CR);
            if (Verbose) printf("  %s%s%s%ldms%s", BD, LatCol(E->Latency), BD, E->Latency, CR);
        } else {
            printf("  %s%s DEAD  %s  %s%s%-6s%s  %s%s%s:%d%s",
                BD, C196, CR, BD, C245, ProtoTag(E->Proto), CR, C245, BD, E->Host, E->Port, CR);
        }
        printf("\n"); Shown++;
    }
    if (!Shown) printf("  %s%s  No entries match the filter.%s\n", BD, C245, CR);
    printf("\n"); Ruler(62, C245);
    time_t El = time(NULL) - StartTime;
    float Rate = (PL->Count > 0) ? ((float)AliveCount*100.0f/(float)PL->Count) : 0.0f;
    printf("  %s%stotal%s %s%s%d%s  %s%salive%s %s%s%d%s  %s%sdead%s %s%s%d%s  %s%selapsed%s %s%s%lds%s  %s%srate%s %s%s%.1f%%%s\n",
        BD, C245, CR, BD, C255, PL->Count, CR,
        BD, C82, CR, BD, C82, AliveCount, CR,
        BD, C196, CR, BD, C196, DeadCount, CR,
        BD, C245, CR, BD, C214, El, CR,
        BD, C245, CR, BD, C226, Rate, CR);
    Ruler(62, C245); printf("\n");
}

static void ExportProxyResults(ProxyList *PL, const char *Fn, FilterMode Filter, int Verbose) {
    FILE *Fp = fopen(Fn, "w");
    if (!Fp) { fprintf(stderr, "  %s%s[ERR]%s Cannot write: %s\n", BD, C196, CR, Fn); return; }
    time_t Now = time(NULL); struct tm *Tm = localtime(&Now); char TB[64];
    strftime(TB, sizeof(TB), "%Y-%m-%d %H:%M:%S", Tm);
    fprintf(Fp, "# HTONSpider v%s  |  %s\n# Total: %d  Alive: %d  Dead: %d\n#\n",
        VersionString, TB, PL->Count, AliveCount, DeadCount);
    if (Filter != FilterDead) {
        fprintf(Fp, "# -- ALIVE --\n");
        for (int i = 0; i < PL->Count; i++) {
            ProxyEntry *E = &PL->Entries[i];
            if (E->Status != StatusAlive) continue;
            if (Verbose) fprintf(Fp, "%s:%d  # %s  %ldms\n", E->Host, E->Port, ProtoTag(E->Proto), E->Latency);
            else         fprintf(Fp, "%s:%d\n", E->Host, E->Port);
        }
    }
    if (Filter != FilterAlive) {
        fprintf(Fp, "#\n# -- DEAD --\n");
        for (int i = 0; i < PL->Count; i++) {
            ProxyEntry *E = &PL->Entries[i];
            if (E->Status != StatusDead) continue;
            fprintf(Fp, "%s:%d\n", E->Host, E->Port);
        }
    }
    fclose(Fp);
    printf("  %s%s[✓]%s Saved to %s%s%s%s\n\n", BD, C82, CR, BD, C87, Fn, CR);
}

static ProxyProto ParseProto(const char *S) {
    if (strcasecmp(S,"socks5")==0) return ProtoSocks5;
    if (strcasecmp(S,"socks4")==0) return ProtoSocks4;
    if (strcasecmp(S,"http"  )==0) return ProtoHTTP;
    if (strcasecmp(S,"auto"  )==0) return ProtoAuto;
    fprintf(stderr, "  %s%s[ERR]%s Unknown protocol: %s\n", BD, C196, CR, S);
    exit(1);
}

static void ModuleProxy(int Argc, char **Argv) {
    memset(&GlobalPCfg, 0, sizeof(GlobalPCfg));
    strncpy(GlobalPCfg.ExportFile, DefaultExport, sizeof(GlobalPCfg.ExportFile)-1);
    GlobalPCfg.Port    = DefaultPort;
    GlobalPCfg.Timeout = DefaultTimeout;
    GlobalPCfg.Threads = DefaultThreads;
    GlobalPCfg.Filter  = FilterNone;
    GlobalPCfg.Proto   = ProtoAuto;

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))            { GlobalPCfg.HelpRequested=1; }
        else if (!strcmp(Argv[i],"-E"))            { GlobalPCfg.ExportEnabled=1; }
        else if (!strcmp(Argv[i],"-v"))            { GlobalPCfg.Verbose=1; }
        else if (!strcmp(Argv[i],"-s")&&i+1<Argc) { strncpy(GlobalPCfg.Source,     Argv[++i],sizeof(GlobalPCfg.Source)-1);     GlobalPCfg.HasSource=1; }
        else if (!strcmp(Argv[i],"-L")&&i+1<Argc) { strncpy(GlobalPCfg.LoadFile,   Argv[++i],sizeof(GlobalPCfg.LoadFile)-1);   GlobalPCfg.HasLoadFile=1; }
        else if (!strcmp(Argv[i],"-e")&&i+1<Argc) { strncpy(GlobalPCfg.ExportFile, Argv[++i],sizeof(GlobalPCfg.ExportFile)-1); GlobalPCfg.ExportEnabled=1; }
        else if (!strcmp(Argv[i],"-P")&&i+1<Argc) { GlobalPCfg.Proto   = ParseProto(Argv[++i]); }
        else if (!strcmp(Argv[i],"-p")&&i+1<Argc) { GlobalPCfg.Port    = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { GlobalPCfg.Timeout = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-T")&&i+1<Argc) { GlobalPCfg.Threads = atoi(Argv[++i]); if (GlobalPCfg.Threads>1000) GlobalPCfg.Threads=1000; }
        else if (!strcmp(Argv[i],"-F")&&i+1<Argc) {
            i++;
            if      (!strcmp(Argv[i],"alive")) GlobalPCfg.Filter=FilterAlive;
            else if (!strcmp(Argv[i],"dead"))  GlobalPCfg.Filter=FilterDead;
        }
    }

    if (GlobalPCfg.HelpRequested) {
        printf("  %s%sproxy%s module\n\n", BD, C51, CR);
        printf("  %s%s-s%s %s<host:port>%s       Single proxy\n",           BD, C226, CR, C87, CR);
        printf("  %s%s-L%s %s<file>%s            Load list from file\n",    BD, C226, CR, C87, CR);
        printf("  %s%s-P%s %s<proto>%s           http|socks4|socks5|auto\n",BD, C226, CR, C87, CR);
        printf("  %s%s-p%s %s<port>%s            Default port\n",           BD, C226, CR, C87, CR);
        printf("  %s%s-t%s %s<sec>%s             Timeout (def: %d)\n",      BD, C226, CR, C87, CR, DefaultTimeout);
        printf("  %s%s-T%s %s<count>%s           Threads (def: %d)\n",      BD, C226, CR, C87, CR, DefaultThreads);
        printf("  %s%s-E%s                  Export to checked.txt\n",        BD, C226, CR);
        printf("  %s%s-e%s %s<file>%s            Custom export file\n",     BD, C226, CR, C87, CR);
        printf("  %s%s-F%s %s<alive|dead>%s      Filter output\n",          BD, C226, CR, C87, CR);
        printf("  %s%s-v%s                  Verbose (latency)\n\n",          BD, C226, CR);
        return;
    }

    if (!GlobalPCfg.HasSource && !GlobalPCfg.HasLoadFile) {
        fprintf(stderr, "  %s%s[ERR]%s Use -s or -L  (-h for help)\n\n", BD, C196, CR); return;
    }

    InitProxyList(&GlobalList);
    if (GlobalPCfg.HasSource) {
        char H[256]; int P;
        ParseHostPort(GlobalPCfg.Source, H, &P, GlobalPCfg.Port);
        AddProxy(&GlobalList, H, P, GlobalPCfg.Proto);
        printf("  %s%s[+]%s %s%s%s:%d%s  proto: %s%s%s%s\n",
            BD, C82, CR, BD, C255, H, P, CR, BD, C226, ProtoTag(GlobalPCfg.Proto), CR);
    }
    if (GlobalPCfg.HasLoadFile)
        LoadProxiesFromFile(&GlobalList, GlobalPCfg.LoadFile, GlobalPCfg.Port, GlobalPCfg.Proto);
    if (!GlobalList.Count) {
        fprintf(stderr, "  %s%s[ERR]%s No proxies to check.\n\n", BD, C196, CR);
        FreeProxyList(&GlobalList); return;
    }
    RunProxyChecks(&GlobalList, GlobalPCfg.Timeout, GlobalPCfg.Threads, GlobalPCfg.Proto);
    PrintProxyResults(&GlobalList, GlobalPCfg.Filter, GlobalPCfg.Verbose);
    if (GlobalPCfg.ExportEnabled)
        ExportProxyResults(&GlobalList, GlobalPCfg.ExportFile, GlobalPCfg.Filter, GlobalPCfg.Verbose);
    FreeProxyList(&GlobalList);
}

typedef struct { char Host[256]; int StartPort; int EndPort; int Timeout; int Verbose; int UdpMode; } ScanArgs;
typedef struct { ScanArgs *Args; int Port; } ScanWorkerArg;
static volatile int ScanDone = 0;
static pthread_mutex_t ScanLock = PTHREAD_MUTEX_INITIALIZER;
static PortResult ScanResults[65536];

static void *ScanWorker(void *Arg) {
    ScanWorkerArg *SA = (ScanWorkerArg*)Arg;
    int Port = SA->Port;
    long Lat = 0;
    int Fd = TcpConnect(SA->Args->Host, Port, SA->Args->Timeout, &Lat);
    pthread_mutex_lock(&ScanLock);
    ScanDone++;
    if (Fd >= 0) {
        ScanResults[Port].Open = 1;
        ScanResults[Port].Latency = Lat;
        const char *Svc = KnownService(Port);
        strncpy(ScanResults[Port].Service, Svc, sizeof(ScanResults[Port].Service)-1);
        if (SA->Args->Verbose) {
            unsigned char Banner[256]; memset(Banner, 0, sizeof(Banner));
            fd_set R; struct timeval Tv = { 1, 0 };
            FD_ZERO(&R); FD_SET(Fd, &R);
            if (select(Fd+1, &R, NULL, NULL, &Tv) > 0)
                recv(Fd, Banner, sizeof(Banner)-1, 0);
            for (int i = 0; i < (int)strlen((char*)Banner); i++)
                if (!isprint(Banner[i]) && Banner[i]!='\n' && Banner[i]!='\r') Banner[i]='.';
            strncpy(ScanResults[Port].Banner, (char*)Banner, sizeof(ScanResults[Port].Banner)-1);
        }
        close(Fd);
    }
    pthread_mutex_unlock(&ScanLock);
    free(SA);
    return NULL;
}

static void ModuleScan(int Argc, char **Argv) {
    char Host[256] = {0};
    int Start = 1, End = 1024, Timeout = 2, Verbose = 0, Threads = 300;

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))            { 
            printf("  %s%sscan%s module\n\n", BD, C226, CR);
            printf("  %s%s-t%s %s<host>%s        Target host/IP\n",         BD, C226, CR, C87, CR);
            printf("  %s%s-p%s %s<start-end>%s   Port range (def: 1-1024)\n",BD, C226, CR, C87, CR);
            printf("  %s%s-T%s %s<threads>%s     Threads (def: 300)\n",     BD, C226, CR, C87, CR);
            printf("  %s%s-w%s %s<sec>%s         Timeout (def: 2)\n",       BD, C226, CR, C87, CR);
            printf("  %s%s-v%s                Grab banners\n\n",             BD, C226, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { strncpy(Host, Argv[++i], sizeof(Host)-1); }
        else if (!strcmp(Argv[i],"-p")&&i+1<Argc) {
            char *Range = Argv[++i];
            char *Dash  = strchr(Range, '-');
            if (Dash) { *Dash='\0'; Start=atoi(Range); End=atoi(Dash+1); }
            else      { Start=End=atoi(Range); }
        }
        else if (!strcmp(Argv[i],"-T")&&i+1<Argc) { Threads = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-w")&&i+1<Argc) { Timeout = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-v"))            { Verbose = 1; }
        else if (Argv[i][0] != '-' && !Host[0])   { strncpy(Host, Argv[i], sizeof(Host)-1); }
    }

    if (!Host[0]) { fprintf(stderr, "  %s%s[ERR]%s No target. Use -t <host>\n\n", BD, C196, CR); return; }

    char IP[64] = {0};
    ResolveStr(Host, IP, sizeof(IP));
    if (!IP[0]) strncpy(IP, Host, sizeof(IP)-1);

    memset(ScanResults, 0, sizeof(ScanResults));
    ScanDone = 0;
    int Total = End - Start + 1;

    printf("\n  %s%s[*]%s Scanning %s%s%s%s (%s%s%s%s)  ports %s%s%d–%d%s  threads %s%s%d%s\n\n",
        BD, C226, CR, BD, C255, Host, CR, C245, BD, IP, CR,
        BD, C226, Start, End, CR, BD, C201, Threads, CR);

    ScanArgs SA = { .Timeout=Timeout, .Verbose=Verbose };
    strncpy(SA.Host, Host, sizeof(SA.Host)-1);

    pthread_t *Thr = (pthread_t*)malloc(sizeof(pthread_t) * Total);
    int Launched = 0, Active = 0;
    time_t T0 = time(NULL);

    for (int Port = Start; Port <= End; Port++) {
        while (Active >= Threads) {
            usleep(2000);
            pthread_mutex_lock(&ScanLock);
            Active = Launched - ScanDone;
            pthread_mutex_unlock(&ScanLock);
        }
        ScanWorkerArg *SWA = (ScanWorkerArg*)malloc(sizeof(ScanWorkerArg));
        SWA->Args = &SA; SWA->Port = Port;
        pthread_create(&Thr[Launched], NULL, ScanWorker, SWA);
        Launched++; Active++;

        pthread_mutex_lock(&ScanLock);
        int D = ScanDone;
        pthread_mutex_unlock(&ScanLock);
        float Pct = (float)D*100.0f/(float)Total;
        printf("\r  %s%s[%s", BD, C245, CR);
        int BW = 24;
        for (int b = 0; b < BW; b++)
            printf(b < (int)(Pct/100.0f*BW) ? "%s%s█%s" : "%s▒%s", (b<(int)(Pct/100.0f*BW)?BD:""), C226, CR);
        printf("%s%s]%s %s%s%5.1f%%%s  port %s%s%d%s     ",
            BD, C245, CR, BD, C255, Pct, CR, BD, C226, Port, CR);
        fflush(stdout);
    }

    for (int i = 0; i < Launched; i++) pthread_join(Thr[i], NULL);
    free(Thr);
    printf("\r%60s\r", "");

    int OpenCount = 0;
    Ruler(62, C226);
    printf("  %s%s  PORT SCAN  —  %s  (%s)%s\n", BD, C255, Host, IP, CR);
    Ruler(62, C226); printf("\n");
    printf("  %s%s%-7s  %-8s  %-12s  %-8s  %s%s\n", BD, C245, "PORT", "STATE", "SERVICE", "LATENCY", "BANNER", CR);
    printf("\n");

    for (int Port = Start; Port <= End; Port++) {
        if (!ScanResults[Port].Open) continue;
        OpenCount++;
        char LatStr[32];
        snprintf(LatStr, sizeof(LatStr), "%ldms", ScanResults[Port].Latency);
        const char *Svc = ScanResults[Port].Service[0] ? ScanResults[Port].Service : "unknown";

        printf("  %s%s%-7d%s  %s%sOPEN%s    %s%s%-12s%s  %s%s%-8s%s",
            BD, C82, Port, CR,
            BD, C46, CR,
            BD, C87, Svc, CR,
            LatCol(ScanResults[Port].Latency), BD, LatStr, CR);
        if (Verbose && ScanResults[Port].Banner[0]) {
            char Short[48]; strncpy(Short, ScanResults[Port].Banner, 47); Short[47]='\0';
            char *NL = strchr(Short, '\n'); if (NL) *NL='\0';
            char *NR = strchr(Short, '\r'); if (NR) *NR='\0';
            printf("  %s%s%s%s", C245, BD, Short, CR);
        }
        printf("\n");
    }

    printf("\n"); Ruler(62, C226);
    printf("  %s%sOpen:%s %s%s%d%s  %s%sClosed/Filtered:%s %s%s%d%s  %s%sTime:%s %s%s%lds%s\n",
        BD, C245, CR, BD, C82,  OpenCount,        CR,
        BD, C245, CR, BD, C196, Total - OpenCount, CR,
        BD, C245, CR, BD, C214, (long)(time(NULL) - T0), CR);
    Ruler(62, C226); printf("\n");
}

static void ModulePing(int Argc, char **Argv) {
    char Host[256] = {0};
    int Count = PingCount, Interval = 1, Timeout = 3, TcpMode = 0, TcpPort = 80;

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))            {
            printf("  %s%sping%s module\n\n", BD, C82, CR);
            printf("  %s%s-t%s %s<host>%s      Target\n",               BD, C226, CR, C87, CR);
            printf("  %s%s-c%s %s<count>%s     Ping count (def: 4)\n",  BD, C226, CR, C87, CR);
            printf("  %s%s-i%s %s<sec>%s       Interval (def: 1)\n",    BD, C226, CR, C87, CR);
            printf("  %s%s-w%s %s<sec>%s       Timeout (def: 3)\n",     BD, C226, CR, C87, CR);
            printf("  %s%s-T%s                TCP ping mode\n",          BD, C226, CR);
            printf("  %s%s-p%s %s<port>%s     TCP port (def: 80)\n\n",  BD, C226, CR, C87, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { strncpy(Host, Argv[++i], sizeof(Host)-1); }
        else if (!strcmp(Argv[i],"-c")&&i+1<Argc) { Count   = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-i")&&i+1<Argc) { Interval= atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-w")&&i+1<Argc) { Timeout = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-T"))            { TcpMode = 1; }
        else if (!strcmp(Argv[i],"-p")&&i+1<Argc) { TcpPort = atoi(Argv[++i]); }
        else if (Argv[i][0] != '-' && !Host[0])   { strncpy(Host, Argv[i], sizeof(Host)-1); }
    }

    if (!Host[0]) { fprintf(stderr, "  %s%s[ERR]%s No target.\n\n", BD, C196, CR); return; }

    char IP[64] = {0};
    ResolveStr(Host, IP, sizeof(IP));
    if (!IP[0]) strncpy(IP, Host, sizeof(IP)-1);

    printf("\n  %s%sPING%s  %s%s%s%s  (%s%s%s%s)  %s%s%s%s\n\n",
        BD, C82, CR, BD, C255, Host, CR, C245, BD, IP, CR,
        C245, BD, TcpMode ? "TCP mode" : "TCP-connect mode", CR);

    long Rtts[1024]; int Sent=0, Recv=0;
    memset(Rtts, 0, sizeof(Rtts));

    for (int i = 0; i < Count && Running; i++) {
        long Lat = 0; int Port = TcpMode ? TcpPort : 80;
        long T0 = GetMs();
        int Fd = TcpConnect(Host, Port, Timeout, &Lat);
        long T1 = GetMs() - T0;
        Sent++;

        if (Fd >= 0) {
            close(Fd); Recv++;
            Rtts[i] = Lat > 0 ? Lat : T1;
            const char *LC = LatCol(Rtts[i]);
            printf("  %s%s[%2d]%s  %s%s%s:%d%s  rtt=%s%ldms%s  %s%sALIVE%s\n",
                BD, C245, i+1, CR,
                BD, C255, Host, Port, CR,
                LC, Rtts[i], CR,
                BD, C82, CR);
        } else {
            printf("  %s%s[%2d]%s  %s%s%s:%d%s  rtt=%s---%s  %s%sTIMEOUT%s\n",
                BD, C245, i+1, CR,
                BD, C255, Host, Port, CR,
                C196, CR,
                BD, C196, CR);
        }
        if (i < Count-1) sleep((unsigned)Interval);
    }

    long Min=999999, Max=0, Sum=0;
    for (int i = 0; i < Count; i++) {
        if (!Rtts[i]) continue;
        if (Rtts[i] < Min) Min = Rtts[i];
        if (Rtts[i] > Max) Max = Rtts[i];
        Sum += Rtts[i];
    }
    long Avg = Recv > 0 ? Sum/Recv : 0;
    float Loss = (float)(Sent-Recv)*100.0f/(float)Sent;

    printf("\n"); Ruler(52, C82);
    printf("  %s%ssent%s %s%s%d%s  %s%srecv%s %s%s%d%s  %s%sloss%s %s%s%.0f%%%s\n",
        BD, C245, CR, BD, C255, Sent, CR,
        BD, C245, CR, BD, C82,  Recv, CR,
        BD, C245, CR, BD, Loss>0?C196:C82, Loss, CR);
    if (Recv > 0)
        printf("  %s%srtt min%s %s%s%ldms%s  %s%savg%s %s%s%ldms%s  %s%smax%s %s%s%ldms%s\n",
            BD, C245, CR, BD, C82, Min, CR,
            BD, C245, CR, BD, C226, Avg, CR,
            BD, C245, CR, BD, C214, Max, CR);
    Ruler(52, C82); printf("\n");
}

static void ModuleTrace(int Argc, char **Argv) {
    char Host[256] = {0};
    int MaxHops = TraceMaxHops, Timeout = 3, Port = 80;

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))            {
            printf("  %s%strace%s module\n\n", BD, C201, CR);
            printf("  %s%s-t%s %s<host>%s      Target\n",              BD, C226, CR, C87, CR);
            printf("  %s%s-m%s %s<hops>%s      Max hops (def: 30)\n",  BD, C226, CR, C87, CR);
            printf("  %s%s-w%s %s<sec>%s       Timeout (def: 3)\n",    BD, C226, CR, C87, CR);
            printf("  %s%s-p%s %s<port>%s      TCP port (def: 80)\n\n",BD, C226, CR, C87, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { strncpy(Host, Argv[++i], sizeof(Host)-1); }
        else if (!strcmp(Argv[i],"-m")&&i+1<Argc) { MaxHops = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-w")&&i+1<Argc) { Timeout = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-p")&&i+1<Argc) { Port    = atoi(Argv[++i]); }
        else if (Argv[i][0] != '-' && !Host[0])   { strncpy(Host, Argv[i], sizeof(Host)-1); }
    }

    if (!Host[0]) { fprintf(stderr, "  %s%s[ERR]%s No target.\n\n", BD, C196, CR); return; }

    struct sockaddr_in Dest;
    if (ResolveToAddr(Host, &Dest) < 0) {
        fprintf(stderr, "  %s%s[ERR]%s Cannot resolve: %s\n\n", BD, C196, CR, Host); return;
    }

    char DestIP[64];
    inet_ntop(AF_INET, &Dest.sin_addr, DestIP, sizeof(DestIP));

    printf("\n  %s%sTRACEROUTE%s  %s%s%s%s  (%s%s%s%s)  max %s%s%d%s hops\n\n",
        BD, C201, CR, BD, C255, Host, CR, C245, BD, DestIP, CR, BD, C226, MaxHops, CR);
    printf("  %s%s%-4s  %-18s  %-8s%s\n\n", BD, C245, "HOP", "ADDRESS", "RTT", CR);
    (void)Port;

    for (int Ttl = 1; Ttl <= MaxHops && Running; Ttl++) {
        int Sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (Sock < 0) break;

        setsockopt(Sock, IPPROTO_IP, IP_TTL, &Ttl, sizeof(Ttl));
        struct timeval Tv = { Timeout, 0 };
        setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, &Tv, sizeof(Tv));

        int RecvSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (RecvSock < 0) { close(Sock); break; }
        setsockopt(RecvSock, SOL_SOCKET, SO_RCVTIMEO, &Tv, sizeof(Tv));

        Dest.sin_port = htons((uint16_t)(33434 + Ttl));
        unsigned char Payload[32]; memset(Payload, 0, sizeof(Payload));

        long T0 = GetMs();
        sendto(Sock, Payload, sizeof(Payload), 0, (struct sockaddr*)&Dest, sizeof(Dest));

        struct sockaddr_in Sender; socklen_t SLen = sizeof(Sender);
        unsigned char Buf[512];
        int N = (int)recvfrom(RecvSock, Buf, sizeof(Buf), 0, (struct sockaddr*)&Sender, &SLen);
        long Rtt = GetMs() - T0;

        close(Sock); close(RecvSock);

        if (N < 0) {
            printf("  %s%s%-3d%s   %s%s*%s\n", BD, C245, Ttl, CR, BD, C196, CR);
            continue;
        }

        char HopIP[64]; inet_ntop(AF_INET, &Sender.sin_addr, HopIP, sizeof(HopIP));
        char HopHost[256]; memset(HopHost, 0, sizeof(HopHost));
        ReverseResolve(HopIP, HopHost, sizeof(HopHost));

        int Reached = (strcmp(HopIP, DestIP) == 0);
        const char *HC = Reached ? C82 : C226;

        if (HopHost[0] && strcmp(HopHost, HopIP) != 0)
            printf("  %s%s%-3d%s   %s%s%-18s%s  %s%s%ldms%s  %s%s%s%s\n",
                BD, C245, Ttl, CR,
                BD, HC, HopIP, CR,
                LatCol(Rtt), BD, Rtt, CR,
                C245, BD, HopHost, CR);
        else
            printf("  %s%s%-3d%s   %s%s%-18s%s  %s%s%ldms%s\n",
                BD, C245, Ttl, CR,
                BD, HC, HopIP, CR,
                LatCol(Rtt), BD, Rtt, CR);

        if (Reached) { printf("\n  %s%s[✓]%s Destination reached in %s%s%d%s hops\n", BD, C82, CR, BD, C255, Ttl, CR); break; }
    }
    printf("\n");
}

static void PrintDnsRecord(const char *Type, const char *Value, const char *Extra) {
    if (Extra && Extra[0])
        printf("  %s%s%-7s%s  %s%s%-50s%s  %s%s%s%s\n",
            BD, C226, Type, CR, BD, C255, Value, CR, C245, BD, Extra, CR);
    else
        printf("  %s%s%-7s%s  %s%s%s%s\n",
            BD, C226, Type, CR, BD, C255, Value, CR);
}

static int DnsBuildQuery(unsigned char *Buf, int BufLen, const char *Host, uint16_t Qtype) {
    memset(Buf, 0, BufLen);
    Buf[0]=0x12; Buf[1]=0x34;
    Buf[2]=0x01; Buf[3]=0x00;
    Buf[4]=0x00; Buf[5]=0x01;
    int Off = 12;
    const char *P = Host;
    while (*P) {
        const char *Dot = strchr(P, '.');
        int Len = Dot ? (int)(Dot - P) : (int)strlen(P);
        if (Off + Len + 1 >= BufLen) return -1;
        Buf[Off++] = (unsigned char)Len;
        memcpy(Buf + Off, P, Len);
        Off += Len;
        if (!Dot) break;
        P = Dot + 1;
    }
    Buf[Off++] = 0x00;
    Buf[Off++] = (Qtype >> 8) & 0xFF;
    Buf[Off++] = Qtype & 0xFF;
    Buf[Off++] = 0x00;
    Buf[Off++] = 0x01;
    return Off;
}

static int DnsExpandName(const unsigned char *Pkt, int PktLen, int Off,
                          char *Out, int OutLen) {
    int Jumped = 0, JumpOff = -1, Steps = 0;
    int Pos = Off; Out[0] = '\0'; int OutOff = 0;
    while (Pos < PktLen && Steps++ < 128) {
        unsigned char Len = Pkt[Pos];
        if ((Len & 0xC0) == 0xC0) {
            if (Pos + 1 >= PktLen) return -1;
            int NewOff = ((Len & 0x3F) << 8) | Pkt[Pos + 1];
            if (!Jumped) JumpOff = Pos + 2;
            Pos = NewOff; Jumped = 1; continue;
        }
        if (Len == 0) { Pos++; break; }
        Pos++;
        if (OutOff > 0 && OutOff < OutLen - 1) Out[OutOff++] = '.';
        int Copy = (Len < OutLen - OutOff - 1) ? Len : OutLen - OutOff - 1;
        memcpy(Out + OutOff, Pkt + Pos, Copy);
        OutOff += Copy; Pos += Len;
    }
    Out[OutOff] = '\0';
    return Jumped ? JumpOff : Pos;
}

static int DnsSendQuery(const char *Server, unsigned char *QBuf, int QLen,
                         unsigned char *RBuf, int RBufLen) {
    int Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (Sock < 0) return -1;
    struct sockaddr_in SA; memset(&SA, 0, sizeof(SA));
    SA.sin_family = AF_INET;
    SA.sin_port   = htons(53);
    inet_pton(AF_INET, Server, &SA.sin_addr);
    struct timeval Tv = { DnsTimeout, 0 };
    setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, &Tv, sizeof(Tv));
    if (sendto(Sock, QBuf, QLen, 0, (struct sockaddr*)&SA, sizeof(SA)) < 0) {
        close(Sock); return -1;
    }
    int N = (int)recv(Sock, RBuf, RBufLen, 0);
    close(Sock);
    return N;
}

static void DnsQuery(const char *Host, uint16_t Qtype, const char *TypeName,
                      const char *Server) {
    unsigned char QBuf[512], RBuf[4096];
    int QLen = DnsBuildQuery(QBuf, sizeof(QBuf), Host, Qtype);
    if (QLen < 0) return;
    int RLen = DnsSendQuery(Server, QBuf, QLen, RBuf, sizeof(RBuf));
    if (RLen < 12) return;

    int Ancount = (RBuf[6] << 8) | RBuf[7];
    if (Ancount <= 0) return;

    int Off = 12;
    char Tmp[256];
    int Skip = DnsExpandName(RBuf, RLen, Off, Tmp, sizeof(Tmp));
    if (Skip < 0) return;
    Off = Skip + 4;

    for (int i = 0; i < Ancount && Off + 10 < RLen; i++) {
        int NameEnd = DnsExpandName(RBuf, RLen, Off, Tmp, sizeof(Tmp));
        if (NameEnd < 0) break;
        Off = NameEnd;
        if (Off + 10 > RLen) break;
        uint16_t RType  = (RBuf[Off] << 8) | RBuf[Off+1];
        uint16_t RDLen  = (RBuf[Off+8] << 8) | RBuf[Off+9];
        Off += 10;
        if (Off + RDLen > RLen) break;

        if (RType == Qtype) {
            char Val[512] = {0};
            if (Qtype == 1 && RDLen == 4) {
                snprintf(Val, sizeof(Val), "%d.%d.%d.%d",
                    RBuf[Off], RBuf[Off+1], RBuf[Off+2], RBuf[Off+3]);
                PrintDnsRecord(TypeName, Val, NULL);
            } else if (Qtype == 28 && RDLen == 16) {
                struct in6_addr A6; memcpy(&A6, RBuf+Off, 16);
                inet_ntop(AF_INET6, &A6, Val, sizeof(Val));
                PrintDnsRecord(TypeName, Val, NULL);
            } else if (Qtype == 15) {
                uint16_t Prio = (RBuf[Off] << 8) | RBuf[Off+1];
                DnsExpandName(RBuf, RLen, Off+2, Val, sizeof(Val));
                char Extra[32]; snprintf(Extra, sizeof(Extra), "prio=%d", Prio);
                PrintDnsRecord(TypeName, Val, Extra);
            } else if (Qtype == 2 || Qtype == 5) {
                DnsExpandName(RBuf, RLen, Off, Val, sizeof(Val));
                PrintDnsRecord(TypeName, Val, NULL);
            } else if (Qtype == 16) {
                int TLen = RBuf[Off]; int TL = TLen < 511 ? TLen : 511;
                memcpy(Val, RBuf+Off+1, TL); Val[TL] = '\0';
                PrintDnsRecord(TypeName, Val, NULL);
            } else if (Qtype == 6) {
                char MName[256] = {0}, RName[256] = {0};
                int P2 = DnsExpandName(RBuf, RLen, Off, MName, sizeof(MName));
                if (P2 > 0) DnsExpandName(RBuf, RLen, P2, RName, sizeof(RName));
                PrintDnsRecord(TypeName, MName, RName);
            }
        }
        Off += RDLen;
    }
}

static void ModuleDns(int Argc, char **Argv) {
    char Host[256] = {0};
    char Server[64] = "8.8.8.8";

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))            {
            printf("  %s%sdns%s module\n\n", BD, C214, CR);
            printf("  %s%s-t%s %s<host>%s      Target domain\n",          BD, C226, CR, C87, CR);
            printf("  %s%s-s%s %s<server>%s    DNS server (def: 8.8.8.8)\n\n", BD, C226, CR, C87, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { strncpy(Host,   Argv[++i], sizeof(Host)-1); }
        else if (!strcmp(Argv[i],"-s")&&i+1<Argc) { strncpy(Server, Argv[++i], sizeof(Server)-1); }
        else if (Argv[i][0] != '-' && !Host[0])   { strncpy(Host,   Argv[i],   sizeof(Host)-1); }
    }

    if (!Host[0]) { fprintf(stderr, "  %s%s[ERR]%s No target.\n\n", BD, C196, CR); return; }

    printf("\n  %s%sDNS LOOKUP%s  %s%s%s%s  %s%s@%s%s\n\n",
        BD, C214, CR, BD, C255, Host, CR, C245, BD, Server, CR);
    Ruler(62, C214);
    printf("  %s%s%-7s  %-50s%s\n\n", BD, C245, "TYPE", "VALUE", CR);

    DnsQuery(Host, 1,  "A",     Server);
    DnsQuery(Host, 28, "AAAA",  Server);
    DnsQuery(Host, 15, "MX",    Server);
    DnsQuery(Host, 2,  "NS",    Server);
    DnsQuery(Host, 16, "TXT",   Server);
    DnsQuery(Host, 5,  "CNAME", Server);
    DnsQuery(Host, 6,  "SOA",   Server);

    printf("\n"); Ruler(62, C214); printf("\n");
}

static void ModuleWhois(int Argc, char **Argv) {
    char Target[256] = {0};

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))          {
            printf("  %s%swhois%s module\n\n", BD, C87, CR);
            printf("  %s%s-t%s %s<ip|domain>%s  Target\n\n", BD, C226, CR, C87, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { strncpy(Target, Argv[++i], sizeof(Target)-1); }
        else if (Argv[i][0] != '-' && !Target[0]) { strncpy(Target, Argv[i], sizeof(Target)-1); }
    }

    if (!Target[0]) { fprintf(stderr, "  %s%s[ERR]%s No target.\n\n", BD, C196, CR); return; }

    char IP[64] = {0};
    ResolveStr(Target, IP, sizeof(IP));
    if (!IP[0]) strncpy(IP, Target, sizeof(IP)-1);

    printf("\n  %s%sWHOIS%s  %s%s%s%s  (%s%s%s%s)\n\n", BD, C87, CR, BD, C255, Target, CR, C245, BD, IP, CR);

    const char *WhoisServers[] = { "whois.iana.org", "whois.apnic.net", "whois.ripe.net", "whois.arin.net", NULL };

    for (int s = 0; WhoisServers[s]; s++) {
        long Lat = 0;
        int Fd = TcpConnect(WhoisServers[s], 43, 5, &Lat);
        if (Fd < 0) continue;

        char Query[512];
        snprintf(Query, sizeof(Query), "%s\r\n", IP);
        SendAll(Fd, (unsigned char*)Query, (int)strlen(Query));

        char Buf[8192]; memset(Buf, 0, sizeof(Buf));
        int Total = 0;
        fd_set R; struct timeval Tv = { 5, 0 };
        while (1) {
            FD_ZERO(&R); FD_SET(Fd, &R);
            Tv.tv_sec = 5; Tv.tv_usec = 0;
            if (select(Fd+1, &R, NULL, NULL, &Tv) <= 0) break;
            int N = (int)recv(Fd, Buf+Total, sizeof(Buf)-Total-1, 0);
            if (N <= 0) break;
            Total += N;
        }
        close(Fd);

        if (Total > 0) {
            Ruler(62, C87);
            printf("  %s%s%s%s\n", C245, BD, WhoisServers[s], CR);
            Ruler(62, C87); printf("\n");

            char *Line = strtok(Buf, "\n");
            while (Line) {
                TrimLine(Line);
                if (Line[0] && Line[0] != '#' && Line[0] != '%') {
                    char *Colon = strchr(Line, ':');
                    if (Colon) {
                        *Colon = '\0';
                        char *Val = Colon + 1;
                        while (*Val == ' ') Val++;
                        printf("  %s%s%-20s%s  %s%s%s%s\n", BD, C226, Line, CR, BD, C255, Val, CR);
                    } else {
                        printf("  %s%s%s%s\n", C245, BD, Line, CR);
                    }
                }
                Line = strtok(NULL, "\n");
            }
            printf("\n");
            break;
        }
    }
}

static void ModuleHTTP(int Argc, char **Argv) {
    char Url[512] = {0};
    int FollowRedirect = 0, ShowBody = 0, Timeout = 10;
    char Method[16] = "GET";

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))            {
            printf("  %s%shttp%s module\n\n", BD, C39, CR);
            printf("  %s%s-u%s %s<url>%s       Target URL\n",             BD, C226, CR, C87, CR);
            printf("  %s%s-L%s              Follow redirects\n",           BD, C226, CR);
            printf("  %s%s-b%s              Show response body\n",         BD, C226, CR);
            printf("  %s%s-m%s %s<method>%s  HTTP method (def: GET)\n",   BD, C226, CR, C87, CR);
            printf("  %s%s-w%s %s<sec>%s     Timeout (def: 10)\n\n",       BD, C226, CR, C87, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-u")&&i+1<Argc) { strncpy(Url, Argv[++i], sizeof(Url)-1); }
        else if (!strcmp(Argv[i],"-m")&&i+1<Argc) { strncpy(Method, Argv[++i], sizeof(Method)-1); }
        else if (!strcmp(Argv[i],"-w")&&i+1<Argc) { Timeout = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-L"))            { FollowRedirect = 1; }
        else if (!strcmp(Argv[i],"-b"))            { ShowBody = 1; }
        else if (Argv[i][0] != '-' && !Url[0])    { strncpy(Url, Argv[i], sizeof(Url)-1); }
    }

    if (!Url[0]) { fprintf(stderr, "  %s%s[ERR]%s No URL.\n\n", BD, C196, CR); return; }

    char Proto2[8] = "http", Host[256] = {0}, Path[512] = "/";
    int Port2 = 80;

    char *Slash = strstr(Url, "://");
    if (Slash) {
        size_t PLen = (size_t)(Slash - Url);
        if (PLen < sizeof(Proto2)) { memcpy(Proto2, Url, PLen); Proto2[PLen]='\0'; }
        Slash += 3;
    } else {
        Slash = Url;
    }

    if (strcasecmp(Proto2, "https") == 0) Port2 = 443;

    char *PathStart = strchr(Slash, '/');
    if (PathStart) {
        strncpy(Path, PathStart, sizeof(Path)-1);
        size_t HL = (size_t)(PathStart - Slash);
        if (HL >= sizeof(Host)) HL = sizeof(Host)-1;
        memcpy(Host, Slash, HL); Host[HL]='\0';
    } else {
        strncpy(Host, Slash, sizeof(Host)-1);
    }

    char *ColonPort = strchr(Host, ':');
    if (ColonPort) { Port2 = atoi(ColonPort+1); *ColonPort='\0'; }

    printf("\n  %s%sHTTP%s  %s%s%s %s%s%s%s:%d%s%s%s\n\n",
        BD, C39, CR, BD, C226, Method, CR, BD, C255, Host, Port2, Path, CR, CR);

    long Lat = 0;
    int Fd = TcpConnect(Host, Port2, Timeout, &Lat);
    if (Fd < 0) {
        fprintf(stderr, "  %s%s[ERR]%s Cannot connect to %s:%d\n\n", BD, C196, CR, Host, Port2);
        return;
    }

    char Req[1024];
    snprintf(Req, sizeof(Req),
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: HTONSpider/%s\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n",
        Method, Path, Host, VersionString);
    SendAll(Fd, (unsigned char*)Req, (int)strlen(Req));

    char Resp[65536]; memset(Resp, 0, sizeof(Resp));
    int Total = 0;
    fd_set R; struct timeval Tv;
    while (Total < (int)sizeof(Resp)-1) {
        FD_ZERO(&R); FD_SET(Fd, &R);
        Tv.tv_sec=Timeout; Tv.tv_usec=0;
        if (select(Fd+1, &R, NULL, NULL, &Tv) <= 0) break;
        int N = (int)recv(Fd, Resp+Total, sizeof(Resp)-Total-1, 0);
        if (N <= 0) break;
        Total += N;
    }
    close(Fd);

    Ruler(62, C39);
    printf("  %s%sRESPONSE HEADERS%s  %s%s(connect: %ldms)%s\n\n", BD, C255, CR, C245, BD, Lat, CR);

    char *HeaderEnd = strstr(Resp, "\r\n\r\n");
    if (!HeaderEnd) HeaderEnd = strstr(Resp, "\n\n");
    char *BodyStart = HeaderEnd ? HeaderEnd + (strncmp(HeaderEnd,"\r\n",2)==0 ? 4 : 2) : NULL;

    char Headers[32768]; memset(Headers, 0, sizeof(Headers));
    if (HeaderEnd) {
        size_t HLen = (size_t)(HeaderEnd - Resp);
        if (HLen >= sizeof(Headers)) HLen = sizeof(Headers)-1;
        memcpy(Headers, Resp, HLen);
    } else {
        strncpy(Headers, Resp, sizeof(Headers)-1);
    }

    char *Line = strtok(Headers, "\n");
    int FirstLine = 1;
    while (Line) {
        TrimLine(Line);
        if (!Line[0]) { Line = strtok(NULL,"\n"); continue; }
        if (FirstLine) {
            printf("  %s%s%s%s\n", BD, C255, Line, CR);
            FirstLine = 0;
        } else {
            char *Colon = strchr(Line, ':');
            if (Colon) {
                *Colon='\0'; char *Val=Colon+1; while (*Val==' ') Val++;
                printf("  %s%s%-30s%s  %s%s%s%s\n", BD, C226, Line, CR, BD, C255, Val, CR);
            } else {
                printf("  %s%s%s%s\n", C245, BD, Line, CR);
            }
        }
        Line = strtok(NULL,"\n");
    }

    if (ShowBody && BodyStart && *BodyStart) {
        printf("\n  %s%sBODY%s\n", BD, C245, CR);
        Ruler(62, C245);
        int BLen = (int)strlen(BodyStart);
        if (BLen > 2048) BLen = 2048;
        printf("%.*s\n", BLen, BodyStart);
        if ((int)strlen(BodyStart) > 2048)
            printf("  %s%s... (truncated at 2048 bytes)%s\n", C245, BD, CR);
    }

    printf("\n"); Ruler(62, C39); printf("\n");
    (void)FollowRedirect;
}

static void ModuleIfinfo(int Argc, char **Argv) {
    (void)Argc; (void)Argv;

    printf("\n  %s%sNETWORK INTERFACES%s\n\n", BD, C99, CR);
    Ruler(62, C99);
    printf("  %s%s%-14s  %-18s  %-18s%s\n\n", BD, C245, "INTERFACE", "IPv4", "IPv6", CR);

    struct ifaddrs *IfList, *Ifa;
    if (getifaddrs(&IfList) < 0) {
        fprintf(stderr, "  %s%s[ERR]%s getifaddrs failed\n\n", BD, C196, CR); return;
    }

    char LastIface[64] = {0};
    for (Ifa = IfList; Ifa; Ifa = Ifa->ifa_next) {
        if (!Ifa->ifa_addr) continue;
        int Family = Ifa->ifa_addr->sa_family;
        if (Family != AF_INET && Family != AF_INET6) continue;

        int IsNew = strcmp(Ifa->ifa_name, LastIface) != 0;
        if (IsNew) strncpy(LastIface, Ifa->ifa_name, sizeof(LastIface)-1);

        char AddrStr[64] = {0};
        if (Family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)Ifa->ifa_addr)->sin_addr, AddrStr, sizeof(AddrStr));
            char MaskStr[64] = {0};
            if (Ifa->ifa_netmask)
                inet_ntop(AF_INET, &((struct sockaddr_in*)Ifa->ifa_netmask)->sin_addr, MaskStr, sizeof(MaskStr));
            printf("  %s%s%-14s%s  %s%s%-18s%s  %s%s%s%s\n",
                BD, C51, Ifa->ifa_name, CR,
                BD, C82, AddrStr, CR,
                C245, BD, MaskStr, CR);
        } else {
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)Ifa->ifa_addr)->sin6_addr, AddrStr, sizeof(AddrStr));
            printf("  %s%s%-14s%s  %s%s%-18s%s  %s%s%s%s\n",
                BD, C51, Ifa->ifa_name, CR,
                C245, BD, "---", CR,
                BD, C201, AddrStr, CR);
        }
    }
    freeifaddrs(IfList);
    printf("\n"); Ruler(62, C99); printf("\n");
}

static void ModuleBanner(int Argc, char **Argv) {
    char Host[256] = {0};
    int Port2 = 80, Timeout = 5, UdpMode = 0;
    char SendData[512] = {0};

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))            {
            printf("  %s%sbanner%s module\n\n", BD, C46, CR);
            printf("  %s%s-t%s %s<host>%s     Target host\n",            BD, C226, CR, C87, CR);
            printf("  %s%s-p%s %s<port>%s     Port (def: 80)\n",         BD, C226, CR, C87, CR);
            printf("  %s%s-w%s %s<sec>%s      Timeout (def: 5)\n",       BD, C226, CR, C87, CR);
            printf("  %s%s-d%s %s<data>%s     Custom send data\n",        BD, C226, CR, C87, CR);
            printf("  %s%s-u%s              UDP mode\n\n",                BD, C226, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { strncpy(Host, Argv[++i], sizeof(Host)-1); }
        else if (!strcmp(Argv[i],"-p")&&i+1<Argc) { Port2   = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-w")&&i+1<Argc) { Timeout = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-d")&&i+1<Argc) { strncpy(SendData, Argv[++i], sizeof(SendData)-1); }
        else if (!strcmp(Argv[i],"-u"))            { UdpMode = 1; }
        else if (Argv[i][0] != '-' && !Host[0])   { strncpy(Host, Argv[i], sizeof(Host)-1); }
    }

    if (!Host[0]) { fprintf(stderr, "  %s%s[ERR]%s No target.\n\n", BD, C196, CR); return; }

    char IP[64] = {0}; ResolveStr(Host, IP, sizeof(IP));
    if (!IP[0]) strncpy(IP, Host, sizeof(IP)-1);

    printf("\n  %s%sBANNER GRAB%s  %s%s%s%s:%d%s  (%s%s%s%s)  %s%s%s%s\n\n",
        BD, C46, CR, BD, C255, Host, CR, Port2, CR,
        C245, BD, IP, CR,
        BD, C245, UdpMode?"UDP":"TCP", CR);

    if (UdpMode) {
        int Sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (Sock < 0) { fprintf(stderr, "  %s%s[ERR]%s Socket failed.\n\n", BD, C196, CR); return; }
        struct sockaddr_in Addr; memset(&Addr, 0, sizeof(Addr));
        Addr.sin_family = AF_INET;
        Addr.sin_port   = htons((uint16_t)Port2);
        inet_pton(AF_INET, IP, &Addr.sin_addr);
        const char *Payload = SendData[0] ? SendData : "\r\n";
        sendto(Sock, Payload, strlen(Payload), 0, (struct sockaddr*)&Addr, sizeof(Addr));
        struct timeval Tv = { Timeout, 0 };
        setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, &Tv, sizeof(Tv));
        unsigned char Buf[4096]; memset(Buf, 0, sizeof(Buf));
        int N = (int)recv(Sock, Buf, sizeof(Buf)-1, 0);
        close(Sock);
        if (N > 0) {
            for (int i = 0; i < N; i++) if (!isprint(Buf[i]) && Buf[i]!='\n' && Buf[i]!='\r') Buf[i]='.';
            Ruler(62, C46);
            printf("  %s%sRAW RESPONSE%s (%d bytes)\n\n", BD, C255, CR, N);
            printf("%s%s%s%s\n", BD, C82, (char*)Buf, CR);
            Ruler(62, C46);
        } else {
            printf("  %s%s[--]%s No UDP response received.\n", BD, C196, CR);
        }
    } else {
        long Lat = 0;
        int Fd = TcpConnect(Host, Port2, Timeout, &Lat);
        if (Fd < 0) { fprintf(stderr, "  %s%s[ERR]%s Cannot connect.\n\n", BD, C196, CR); return; }

        if (SendData[0]) SendAll(Fd, (unsigned char*)SendData, (int)strlen(SendData));
        else {
            char Req[256];
            snprintf(Req, sizeof(Req), "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", Host);
            SendAll(Fd, (unsigned char*)Req, (int)strlen(Req));
        }

        unsigned char Buf[8192]; memset(Buf, 0, sizeof(Buf));
        int Total = 0;
        fd_set R; struct timeval Tv = { Timeout, 0 };
        while (Total < (int)sizeof(Buf)-1) {
            FD_ZERO(&R); FD_SET(Fd, &R);
            Tv.tv_sec=Timeout; Tv.tv_usec=0;
            if (select(Fd+1, &R, NULL, NULL, &Tv) <= 0) break;
            int N = (int)recv(Fd, Buf+Total, sizeof(Buf)-Total-1, 0);
            if (N <= 0) break;
            Total += N;
        }
        close(Fd);

        for (int i = 0; i < Total; i++)
            if (!isprint(Buf[i]) && Buf[i]!='\n' && Buf[i]!='\r' && Buf[i]!='\t') Buf[i]='.';

        Ruler(62, C46);
        printf("  %s%sRAW BANNER%s  (%d bytes, connect: %ldms)\n\n", BD, C255, CR, Total, Lat);
        printf("%s%s%s%s\n", BD, C245, (char*)Buf, CR);
        Ruler(62, C46);
    }
    printf("\n");
}

static void ModuleSubnet(int Argc, char **Argv) {
    char Input[128] = {0};

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h"))          {
            printf("  %s%ssubnet%s module\n\n", BD, C208, CR);
            printf("  %s%s-t%s %s<ip/cidr>%s   e.g. 192.168.1.0/24\n\n", BD, C226, CR, C87, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t")&&i+1<Argc) { strncpy(Input, Argv[++i], sizeof(Input)-1); }
        else if (Argv[i][0] != '-' && !Input[0])  { strncpy(Input, Argv[i], sizeof(Input)-1); }
    }

    if (!Input[0]) { fprintf(stderr, "  %s%s[ERR]%s No input.\n\n", BD, C196, CR); return; }

    char IPPart[64] = {0}; int Cidr = 32;
    char *Slash = strchr(Input, '/');
    if (Slash) { *Slash='\0'; strncpy(IPPart, Input, sizeof(IPPart)-1); Cidr = atoi(Slash+1); }
    else       { strncpy(IPPart, Input, sizeof(IPPart)-1); }

    struct in_addr Addr;
    if (inet_pton(AF_INET, IPPart, &Addr) != 1) {
        fprintf(stderr, "  %s%s[ERR]%s Invalid IP: %s\n\n", BD, C196, CR, IPPart); return;
    }

    if (Cidr < 0 || Cidr > 32) { fprintf(stderr, "  %s%s[ERR]%s CIDR must be 0-32\n\n", BD, C196, CR); return; }

    uint32_t IP32   = ntohl(Addr.s_addr);
    uint32_t Mask32 = Cidr > 0 ? (0xFFFFFFFF << (32 - Cidr)) : 0;
    uint32_t Net32  = IP32 & Mask32;
    uint32_t Bcast  = Net32 | (~Mask32);
    uint32_t First  = Net32 + 1;
    uint32_t Last   = Bcast - 1;
    uint64_t Hosts  = Cidr <= 30 ? (uint64_t)(1U << (32 - Cidr)) - 2 : (Cidr == 31 ? 2 : 1);

    char NetStr[64], MaskStr[64], BcastStr[64], FirstStr[64], LastStr[64];
    struct in_addr Tmp;

    Tmp.s_addr = htonl(Net32);   inet_ntop(AF_INET, &Tmp, NetStr,   sizeof(NetStr));
    Tmp.s_addr = htonl(Mask32);  inet_ntop(AF_INET, &Tmp, MaskStr,  sizeof(MaskStr));
    Tmp.s_addr = htonl(Bcast);   inet_ntop(AF_INET, &Tmp, BcastStr, sizeof(BcastStr));
    Tmp.s_addr = htonl(First);   inet_ntop(AF_INET, &Tmp, FirstStr, sizeof(FirstStr));
    Tmp.s_addr = htonl(Last);    inet_ntop(AF_INET, &Tmp, LastStr,  sizeof(LastStr));

    printf("\n  %s%sSUBNET CALCULATOR%s  %s%s%s/%d%s\n\n", BD, C208, CR, BD, C255, IPPart, Cidr, CR);
    Ruler(50, C208);

    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD, C226, "Network",     CR, BD, C255, NetStr,   CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD, C226, "Subnet Mask", CR, BD, C255, MaskStr,  CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD, C226, "Broadcast",   CR, BD, C255, BcastStr, CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD, C226, "First Host",  CR, BD, C82,  FirstStr, CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD, C226, "Last Host",   CR, BD, C82,  LastStr,  CR);
    printf("  %s%s%-18s%s  %s%s%llu%s\n",BD, C226, "Usable Hosts",CR, BD, C51,  (unsigned long long)Hosts, CR);
    printf("  %s%s%-18s%s  %s%s/%d%s\n", BD, C226, "CIDR",        CR, BD, C214, Cidr, CR);

    if (Cidr <= 24) {
        char WildStr[64];
        uint32_t Wild = ~Mask32;
        Tmp.s_addr = htonl(Wild); inet_ntop(AF_INET, &Tmp, WildStr, sizeof(WildStr));
        printf("  %s%s%-18s%s  %s%s%s%s\n", BD, C226, "Wildcard Mask", CR, BD, C245, WildStr, CR);
    }

    printf("\n"); Ruler(50, C208); printf("\n");
}

static void PrintModuleHeader(const char *Name, const char *Col) {
    (void)Name; (void)Col;
}

int main(int Argc, char **Argv) {
    signal(SIGINT,  SigHandler);
    signal(SIGTERM, SigHandler);

    PrintBanner();

    if (Argc < 2) { PrintMainHelp(Argv[0]); return 0; }
    if (!strcmp(Argv[1],"-h") || !strcmp(Argv[1],"help") || !strcmp(Argv[1],"--help")) {
        PrintMainHelp(Argv[0]); return 0;
    }

    char *Module = Argv[1];
    int   MArgc  = Argc - 2;
    char **MArgv = Argv + 2;

    if      (!strcmp(Module,"proxy"))  { ModuleProxy(MArgc, MArgv); }
    else if (!strcmp(Module,"scan"))   { ModuleScan(MArgc, MArgv);  }
    else if (!strcmp(Module,"ping"))   { ModulePing(MArgc, MArgv);  }
    else if (!strcmp(Module,"trace"))  { ModuleTrace(MArgc, MArgv); }
    else if (!strcmp(Module,"dns"))    { ModuleDns(MArgc, MArgv);   }
    else if (!strcmp(Module,"whois"))  { ModuleWhois(MArgc, MArgv); }
    else if (!strcmp(Module,"http"))   { ModuleHTTP(MArgc, MArgv);  }
    else if (!strcmp(Module,"ifinfo")) { ModuleIfinfo(MArgc, MArgv);}
    else if (!strcmp(Module,"banner")) { ModuleBanner(MArgc, MArgv);}
    else if (!strcmp(Module,"subnet")) { ModuleSubnet(MArgc, MArgv);}
    else {
        fprintf(stderr, "  %s%s[ERR]%s Unknown module: %s  (use -h for help)\n\n", BD, C196, CR, Module);
        return 1;
    }

    (void)PrintModuleHeader;
    return 0;
}
