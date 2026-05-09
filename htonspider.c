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
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>

#define MaxProxies      65536
#define DefaultPort     1080
#define DefaultTimeout  5
#define DefaultThreads  50
#define DefaultExport   "checked.txt"
#define VersionString   "2.0.0"
#define TestHost        "google.com"
#define TestPort        80
#define Socks4Version   0x04
#define Socks5Version   0x05

typedef enum {
    ProtoHTTP   = 0,
    ProtoSocks4 = 1,
    ProtoSocks5 = 2,
    ProtoAuto   = 3
} ProxyProto;

typedef enum {
    StatusUnknown = 0,
    StatusAlive   = 1,
    StatusDead    = 2
} ProxyStatus;

typedef enum {
    FilterNone  = 0,
    FilterAlive = 1,
    FilterDead  = 2
} FilterMode;

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
    ProxyList   *List;
    int          Index;
    int          Timeout;
    ProxyProto   Proto;
} WorkerArgs;

typedef struct {
    char        Source[256];
    char        ExportFile[256];
    char        LoadFile[256];
    int         Port;
    int         Timeout;
    int         Threads;
    int         ExportEnabled;
    int         HelpRequested;
    int         HasLoadFile;
    int         HasSource;
    int         Verbose;
    FilterMode  Filter;
    ProxyProto  Proto;
} Config;

static ProxyList        GlobalList;
static Config           GlobalConfig;
static volatile int     DoneCount  = 0;
static volatile int     AliveCount = 0;
static volatile int     DeadCount  = 0;
static volatile int     Running    = 1;
static pthread_mutex_t  DoneLock   = PTHREAD_MUTEX_INITIALIZER;
static time_t           StartTime;

static const char *CR  = "\033[0m";
static const char *C51 = "\033[38;5;51m";
static const char *C82 = "\033[38;5;82m";
static const char *C196= "\033[38;5;196m";
static const char *C226= "\033[38;5;226m";
static const char *C201= "\033[38;5;201m";
static const char *C255= "\033[38;5;255m";
static const char *C245= "\033[38;5;245m";
static const char *C214= "\033[38;5;214m";
static const char *C99 = "\033[38;5;99m";
static const char *C87 = "\033[38;5;87m";
static const char *BD  = "\033[1m";

static void SignalHandler(int Sig) { (void)Sig; Running = 0; }

static long GetTimeMs() {
    struct timeval Tv;
    gettimeofday(&Tv, NULL);
    return (long)(Tv.tv_sec * 1000 + Tv.tv_usec / 1000);
}

static void PrintBanner() {
    printf("\n");
    printf("%s%s", C51, BD);
    printf("  ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗\n");
    printf("  ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝\n");
    printf("  ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ \n");
    printf("  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  \n");
    printf("  ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   \n");
    printf("  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   \n");
    printf("%s", CR);
    printf("  %s%sCHECK%s  ", C245, BD, CR);
    printf("%s%sHTTP · SOCKS4 · SOCKS5%s",C245, BD, CR);
    printf("%s%s  ·  v%s%s\n", C245, BD, VersionString, CR);
    printf("  %s%s────────────────────────────────────────────%s\n\n", C245, BD, CR);
}

static void PrintHelp(const char *Prog) {
    PrintBanner();
    printf("  %s%sUSAGE%s\n", BD, C255, CR);
    printf("  %s%s%s <options>%s\n\n", BD, C51, Prog, CR);

    printf("  %s%sSOURCE OPTIONS%s\n", BD, C245, CR);
    printf("  %s%s-s%s %s<ip:port>%s          Single proxy target\n",           BD, C226, CR, C87, CR);
    printf("  %s%s-L%s %s<file>%s             Load proxy list from file\n",      BD, C226, CR, C87, CR);
    printf("  %s%s-p%s %s<port>%s             Default port if unspecified (def: %d)\n\n", BD, C226, CR, C87, CR, DefaultPort);

    printf("  %s%sPROTOCOL%s\n", BD, C245, CR);
    printf("  %s%s-P%s %s<proto>%s            http | socks4 | socks5 | auto (def: auto)\n\n", BD, C226, CR, C87, CR);

    printf("  %s%sOUTPUT%s\n", BD, C245, CR);
    printf("  %s%s-E%s                  Export results to %schecked.txt%s\n",    BD, C226, CR, C87, CR);
    printf("  %s%s-e%s %s<filename>%s        Custom export filename (implies -E)\n", BD, C226, CR, C87, CR);
    printf("  %s%s-F%s %s<alive|dead>%s      Filter output to alive or dead only\n", BD, C226, CR, C87, CR);
    printf("  %s%s-v%s                  Verbose: show latency per proxy\n\n",    BD, C226, CR);

    printf("  %s%sPERFORMANCE%s\n", BD, C245, CR);
    printf("  %s%s-t%s %s<seconds>%s         Connection timeout (def: %d)\n",    BD, C226, CR, C87, CR, DefaultTimeout);
    printf("  %s%s-T%s %s<count>%s           Thread count (def: %d, max: 1000)\n\n", BD, C226, CR, C87, CR, DefaultThreads);

    printf("  %s%sMISC%s\n", BD, C245, CR);
    printf("  %s%s-h%s                  Print this help\n\n", BD, C226, CR);

    printf("  %s%sEXAMPLES%s\n", BD, C245, CR);
    printf("  %s%s%s -s 127.0.0.1:1080 -P socks5 -v%s\n", BD, C245, Prog, CR);
    printf("  %s%s%s -L list.txt -P auto -E -F alive -T 200 -t 3%s\n", BD, C245, Prog, CR);
    printf("  %s%s%s -L list.txt -P socks4 -e socks4_alive.txt -F alive -v%s\n\n", BD, C245, Prog, CR);
}

static int ResolveHost(const char *Host, struct in_addr *OutAddr) {
    struct addrinfo Hints, *Res;
    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family   = AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(Host, NULL, &Hints, &Res) != 0) return -1;
    *OutAddr = ((struct sockaddr_in *)Res->ai_addr)->sin_addr;
    freeaddrinfo(Res);
    return 0;
}

static int ConnectWithTimeout(const char *Host, int Port, int TimeoutSec, long *OutLatency) {
    struct addrinfo Hints, *Res = NULL;
    char PortStr[16];
    int Fd = -1;

    memset(&Hints, 0, sizeof(Hints));
    Hints.ai_family   = AF_UNSPEC;
    Hints.ai_socktype = SOCK_STREAM;
    snprintf(PortStr, sizeof(PortStr), "%d", Port);

    if (getaddrinfo(Host, PortStr, &Hints, &Res) != 0) return -1;

    Fd = socket(Res->ai_family, Res->ai_socktype, Res->ai_protocol);
    if (Fd < 0) { freeaddrinfo(Res); return -1; }

    int Flags = fcntl(Fd, F_GETFL, 0);
    fcntl(Fd, F_SETFL, Flags | O_NONBLOCK);

    long T0 = GetTimeMs();
    connect(Fd, Res->ai_addr, Res->ai_addrlen);
    freeaddrinfo(Res);

    fd_set WSet;
    struct timeval Tv = { TimeoutSec, 0 };
    FD_ZERO(&WSet);
    FD_SET(Fd, &WSet);

    if (select(Fd + 1, NULL, &WSet, NULL, &Tv) <= 0) { close(Fd); return -1; }

    int SockErr = 0;
    socklen_t Len = sizeof(SockErr);
    getsockopt(Fd, SOL_SOCKET, SO_ERROR, &SockErr, &Len);
    if (SockErr != 0) { close(Fd); return -1; }

    if (OutLatency) *OutLatency = GetTimeMs() - T0;
    return Fd;
}

static int SendAll(int Fd, const unsigned char *Buf, int Len) {
    int Sent = 0;
    while (Sent < Len) {
        int N = (int)send(Fd, Buf + Sent, Len - Sent, 0);
        if (N <= 0) return -1;
        Sent += N;
    }
    return 0;
}

static int RecvExact(int Fd, unsigned char *Buf, int Len, int TimeoutSec) {
    int Got = 0;
    while (Got < Len) {
        fd_set RSet;
        struct timeval Tv = { TimeoutSec, 0 };
        FD_ZERO(&RSet);
        FD_SET(Fd, &RSet);
        if (select(Fd + 1, &RSet, NULL, NULL, &Tv) <= 0) return -1;
        int N = (int)recv(Fd, Buf + Got, Len - Got, 0);
        if (N <= 0) return -1;
        Got += N;
    }
    return 0;
}

static ProxyStatus CheckHTTP(const char *Host, int Port, int TimeoutSec, long *OutLatency) {
    long Lat = 0;
    int Fd = ConnectWithTimeout(Host, Port, TimeoutSec, &Lat);
    if (Fd < 0) return StatusDead;

    char Req[512];
    snprintf(Req, sizeof(Req),
        "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
        TestHost, TestPort, TestHost, TestPort);

    if (SendAll(Fd, (unsigned char *)Req, (int)strlen(Req)) < 0) {
        close(Fd); return StatusDead;
    }

    unsigned char Resp[256];
    memset(Resp, 0, sizeof(Resp));
    fd_set RSet;
    struct timeval Tv = { TimeoutSec, 0 };
    FD_ZERO(&RSet);
    FD_SET(Fd, &RSet);

    if (select(Fd + 1, &RSet, NULL, NULL, &Tv) <= 0) { close(Fd); return StatusDead; }
    int N = (int)recv(Fd, Resp, sizeof(Resp) - 1, 0);
    close(Fd);

    if (N < 8) return StatusDead;
    if (strstr((char *)Resp, "200") || strstr((char *)Resp, "HTTP")) {
        if (OutLatency) *OutLatency = Lat;
        return StatusAlive;
    }
    return StatusDead;
}

static ProxyStatus CheckSocks4(const char *Host, int Port, int TimeoutSec, long *OutLatency) {
    long Lat = 0;
    int Fd = ConnectWithTimeout(Host, Port, TimeoutSec, &Lat);
    if (Fd < 0) return StatusDead;

    struct in_addr Target;
    if (ResolveHost(TestHost, &Target) < 0) { close(Fd); return StatusDead; }

    unsigned char Req[9];
    Req[0] = Socks4Version;
    Req[1] = 0x01;
    Req[2] = (TestPort >> 8) & 0xFF;
    Req[3] = TestPort & 0xFF;
    memcpy(&Req[4], &Target.s_addr, 4);
    Req[8] = 0x00;

    if (SendAll(Fd, Req, 9) < 0) { close(Fd); return StatusDead; }

    unsigned char Resp[8];
    if (RecvExact(Fd, Resp, 8, TimeoutSec) < 0) { close(Fd); return StatusDead; }
    close(Fd);

    if (Resp[0] == 0x00 && Resp[1] == 0x5A) {
        if (OutLatency) *OutLatency = Lat;
        return StatusAlive;
    }
    return StatusDead;
}

static ProxyStatus CheckSocks5(const char *Host, int Port, int TimeoutSec, long *OutLatency) {
    long Lat = 0;
    int Fd = ConnectWithTimeout(Host, Port, TimeoutSec, &Lat);
    if (Fd < 0) return StatusDead;

    unsigned char Hello[3] = { Socks5Version, 0x01, 0x00 };
    if (SendAll(Fd, Hello, 3) < 0) { close(Fd); return StatusDead; }

    unsigned char HResp[2];
    if (RecvExact(Fd, HResp, 2, TimeoutSec) < 0) { close(Fd); return StatusDead; }
    if (HResp[0] != Socks5Version || HResp[1] != 0x00) { close(Fd); return StatusDead; }

    size_t HLen = strlen(TestHost);
    unsigned char ConnReq[300];
    int Idx = 0;
    ConnReq[Idx++] = Socks5Version;
    ConnReq[Idx++] = 0x01;
    ConnReq[Idx++] = 0x00;
    ConnReq[Idx++] = 0x03;
    ConnReq[Idx++] = (unsigned char)HLen;
    memcpy(&ConnReq[Idx], TestHost, HLen);
    Idx += (int)HLen;
    ConnReq[Idx++] = (TestPort >> 8) & 0xFF;
    ConnReq[Idx++] = TestPort & 0xFF;

    if (SendAll(Fd, ConnReq, Idx) < 0) { close(Fd); return StatusDead; }

    unsigned char CResp[10];
    if (RecvExact(Fd, CResp, 10, TimeoutSec) < 0) { close(Fd); return StatusDead; }
    close(Fd);

    if (CResp[0] == Socks5Version && CResp[1] == 0x00) {
        if (OutLatency) *OutLatency = Lat;
        return StatusAlive;
    }
    return StatusDead;
}

static ProxyStatus CheckAuto(const char *Host, int Port, int TimeoutSec,
                              long *OutLatency, ProxyProto *OutProto) {
    long Lat = 0;
    ProxyStatus St;

    St = CheckSocks5(Host, Port, TimeoutSec, &Lat);
    if (St == StatusAlive) {
        if (OutLatency) *OutLatency = Lat;
        if (OutProto)   *OutProto   = ProtoSocks5;
        return StatusAlive;
    }
    St = CheckSocks4(Host, Port, TimeoutSec, &Lat);
    if (St == StatusAlive) {
        if (OutLatency) *OutLatency = Lat;
        if (OutProto)   *OutProto   = ProtoSocks4;
        return StatusAlive;
    }
    St = CheckHTTP(Host, Port, TimeoutSec, &Lat);
    if (St == StatusAlive) {
        if (OutLatency) *OutLatency = Lat;
        if (OutProto)   *OutProto   = ProtoHTTP;
        return StatusAlive;
    }
    return StatusDead;
}

static const char *ProtoName(ProxyProto P) {
    switch (P) {
        case ProtoHTTP:   return "HTTP  ";
        case ProtoSocks4: return "SOCKS4";
        case ProtoSocks5: return "SOCKS5";
        case ProtoAuto:   return "AUTO  ";
        default:          return "------";
    }
}

static const char *ProtoColor(ProxyProto P) {
    switch (P) {
        case ProtoHTTP:   return "\033[38;5;39m";
        case ProtoSocks4: return "\033[38;5;201m";
        case ProtoSocks5: return "\033[38;5;226m";
        default:          return "\033[38;5;245m";
    }
}

static const char *LatencyColor(long Ms) {
    if (Ms <  300) return "\033[38;5;82m";
    if (Ms <  800) return "\033[38;5;226m";
    if (Ms < 2000) return "\033[38;5;214m";
    return "\033[38;5;196m";
}

static void *WorkerThread(void *Arg) {
    WorkerArgs *WA    = (WorkerArgs *)Arg;
    ProxyEntry *Entry = &WA->List->Entries[WA->Index];
    long Latency      = 0;
    ProxyProto Detected = WA->Proto;

    switch (WA->Proto) {
        case ProtoSocks5:
            Entry->Status = CheckSocks5(Entry->Host, Entry->Port, WA->Timeout, &Latency);
            Entry->Proto  = ProtoSocks5;
            break;
        case ProtoSocks4:
            Entry->Status = CheckSocks4(Entry->Host, Entry->Port, WA->Timeout, &Latency);
            Entry->Proto  = ProtoSocks4;
            break;
        case ProtoHTTP:
            Entry->Status = CheckHTTP(Entry->Host, Entry->Port, WA->Timeout, &Latency);
            Entry->Proto  = ProtoHTTP;
            break;
        case ProtoAuto:
        default:
            Entry->Status = CheckAuto(Entry->Host, Entry->Port, WA->Timeout, &Latency, &Detected);
            Entry->Proto  = (Entry->Status == StatusAlive) ? Detected : ProtoAuto;
            break;
    }

    Entry->Latency = Latency;

    pthread_mutex_lock(&DoneLock);
    DoneCount++;
    if (Entry->Status == StatusAlive) AliveCount++;
    else DeadCount++;
    pthread_mutex_unlock(&DoneLock);

    free(WA);
    return NULL;
}

static void ParseHostPort(const char *Input, char *OutHost, int *OutPort, int DefPort) {
    const char *Colon = strrchr(Input, ':');
    if (Colon) {
        size_t L = (size_t)(Colon - Input);
        if (L >= 256) L = 255;
        strncpy(OutHost, Input, L);
        OutHost[L] = '\0';
        *OutPort = atoi(Colon + 1);
        if (*OutPort <= 0 || *OutPort > 65535) *OutPort = DefPort;
    } else {
        strncpy(OutHost, Input, 255);
        OutHost[255] = '\0';
        *OutPort = DefPort;
    }
}

static void InitProxyList(ProxyList *PL) {
    PL->Entries  = (ProxyEntry *)malloc(sizeof(ProxyEntry) * MaxProxies);
    PL->Count    = 0;
    PL->Capacity = MaxProxies;
    pthread_mutex_init(&PL->Lock, NULL);
}

static void FreeProxyList(ProxyList *PL) {
    free(PL->Entries);
    pthread_mutex_destroy(&PL->Lock);
}

static void AddProxy(ProxyList *PL, const char *Host, int Port, ProxyProto Proto) {
    pthread_mutex_lock(&PL->Lock);
    if (PL->Count < PL->Capacity) {
        ProxyEntry *E = &PL->Entries[PL->Count];
        strncpy(E->Host, Host, 255);
        E->Host[255] = '\0';
        E->Port      = Port;
        E->Status    = StatusUnknown;
        E->Proto     = Proto;
        E->Latency   = 0;
        PL->Count++;
    }
    pthread_mutex_unlock(&PL->Lock);
}

static void TrimLine(char *S) {
    size_t L = strlen(S);
    while (L > 0 && (S[L-1] == '\n' || S[L-1] == '\r' || S[L-1] == ' ')) S[--L] = '\0';
    char *P = S;
    while (*P && (*P == ' ' || *P == '\t')) P++;
    if (P != S) memmove(S, P, strlen(P) + 1);
}

static void LoadFromFile(ProxyList *PL, const char *Filename, int DefPort, ProxyProto Proto) {
    FILE *Fp = fopen(Filename, "r");
    if (!Fp) {
        fprintf(stderr, "\n  %s%s[ERR]%s Cannot open: %s\n\n", BD, C196, CR, Filename);
        exit(1);
    }
    char Line[512];
    int Loaded = 0;
    while (fgets(Line, sizeof(Line), Fp)) {
        TrimLine(Line);
        if (Line[0] == '\0' || Line[0] == '#') continue;
        char Host[256];
        int Port;
        ParseHostPort(Line, Host, &Port, DefPort);
        AddProxy(PL, Host, Port, Proto);
        Loaded++;
    }
    fclose(Fp);
    printf("  %s%s[+]%s Loaded %s%s%d%s entr%s from %s%s%s%s\n",
        BD, C82, CR,
        BD, C255, Loaded, CR,
        Loaded == 1 ? "y" : "ies",
        BD, C87, Filename, CR);
}

static void DrawProgressBar(int Done, int Total, int Alive, int Dead, int Active) {
    int BarWidth = 28;
    int Filled   = (Total > 0) ? (Done * BarWidth / Total) : 0;

    time_t Elapsed = time(NULL) - StartTime;
    int Remaining  = 0;
    if (Done > 0 && Elapsed > 0) {
        int Rate  = (int)((float)Done / (float)Elapsed);
        int Left  = Total - Done;
        Remaining = (Rate > 0) ? Left / Rate : 0;
    }

    float Pct = (Total > 0) ? ((float)Done * 100.0f / (float)Total) : 0.0f;

    printf("\r  ");
    printf("%s%s[%s", BD, C245, CR);
    for (int i = 0; i < BarWidth; i++) {
        if (i < Filled) printf("%s%s█%s", BD, C51, CR);
        else            printf("%s▒%s", C245, CR);
    }
    printf("%s%s]%s", BD, C245, CR);
    printf(" %s%s%5.1f%%%s", BD, C255, Pct, CR);
    printf("  %s%s%d/%d%s", C245, BD, Done, Total, CR);
    printf("  %s%s%s+%d%s", BD, C82, BD, Alive, CR);
    printf("  %s%s%s-%d%s", BD, C196, BD, Dead, CR);
    printf("  %s%s~%ds%s", C214, BD, Remaining, CR);
    printf("  %s%s[%dT]%s", C99, BD, Active, CR);
    fflush(stdout);
}

static void RunChecks(ProxyList *PL, int TimeoutSec, int MaxThreads, ProxyProto Proto) {
    int Total    = PL->Count;
    int Active   = 0;
    int Launched = 0;

    StartTime = time(NULL);

    printf("\n  %s%s[*]%s %s%s%d%s proxies  ",
        BD, C51, CR, BD, C255, Total, CR);
    printf("%sproto:%s %s%s%s%s  ",
        C245, CR, BD, ProtoColor(Proto), ProtoName(Proto), CR);
    printf("%sthreads:%s %s%s%d%s  ",
        C245, CR, BD, C201, MaxThreads, CR);
    printf("%stimeout:%s %s%s%ds%s\n\n",
        C245, CR, BD, C214, TimeoutSec, CR);

    pthread_t *Threads = (pthread_t *)malloc(sizeof(pthread_t) * Total);

    while (Running && (Launched < Total || Active > 0)) {
        while (Active < MaxThreads && Launched < Total && Running) {
            WorkerArgs *WA = (WorkerArgs *)malloc(sizeof(WorkerArgs));
            WA->List    = PL;
            WA->Index   = Launched;
            WA->Timeout = TimeoutSec;
            WA->Proto   = Proto;
            pthread_create(&Threads[Launched], NULL, WorkerThread, WA);
            Launched++;
            Active++;
        }
        usleep(10000);

        pthread_mutex_lock(&DoneLock);
        int Done  = DoneCount;
        int Alive = AliveCount;
        int Dead  = DeadCount;
        pthread_mutex_unlock(&DoneLock);

        Active = Launched - Done;
        DrawProgressBar(Done, Total, Alive, Dead, Active);
    }

    for (int i = 0; i < Launched; i++) pthread_join(Threads[i], NULL);
    free(Threads);

    DrawProgressBar(Total, Total, AliveCount, DeadCount, 0);
    printf("\n");
}

static void PrintLine(int Width) {
    printf("  %s%s", C245, BD);
    for (int i = 0; i < Width; i++) printf("─");
    printf("%s\n", CR);
}

static void PrintResults(ProxyList *PL, FilterMode Filter, int Verbose) {
    int Width = 62;
    printf("\n");
    PrintLine(Width);
    printf("  %s%s  RESULTS                                              %s\n", BD, C255, CR);
    PrintLine(Width);
    printf("\n");

    int Shown = 0;
    for (int i = 0; i < PL->Count; i++) {
        ProxyEntry *E = &PL->Entries[i];
        if (Filter == FilterAlive && E->Status != StatusAlive) continue;
        if (Filter == FilterDead  && E->Status != StatusDead)  continue;

        if (E->Status == StatusAlive) {
            char AddrBuf[300];
            snprintf(AddrBuf, sizeof(AddrBuf), "%s:%d", E->Host, E->Port);
            printf("  %s%s ALIVE %s  ", BD, C82, CR);
            printf("%s%s%s%-6s%s  ", BD, ProtoColor(E->Proto), BD, ProtoName(E->Proto), CR);
            printf("%s%s%-42s%s", BD, C255, AddrBuf, CR);
            if (Verbose) {
                printf("  %s%s%s%ldms%s",
                    BD, LatencyColor(E->Latency), BD, E->Latency, CR);
            }
        } else {
            printf("  %s%s DEAD  %s  ", BD, C196, CR);
            printf("%s%s%-6s%s  ", BD, C245, ProtoName(E->Proto), CR);
            printf("%s%s%s:%d%s", C245, BD, E->Host, E->Port, CR);
        }
        printf("\n");
        Shown++;
    }

    if (Shown == 0) {
        printf("  %s%s  No entries match the current filter.%s\n", BD, C245, CR);
    }

    printf("\n");
    PrintLine(Width);

    time_t Elapsed = time(NULL) - StartTime;
    float Rate = (PL->Count > 0) ? ((float)AliveCount * 100.0f / (float)PL->Count) : 0.0f;

    printf("  %s%stotal%s %s%s%d%s  ",
        BD, C245, CR, BD, C255, PL->Count, CR);
    printf("%s%salive%s %s%s%d%s  ",
        BD, C82, CR, BD, C82, AliveCount, CR);
    printf("%s%sdead%s %s%s%d%s  ",
        BD, C196, CR, BD, C196, DeadCount, CR);
    printf("%s%selapsed%s %s%s%lds%s  ",
        BD, C245, CR, BD, C214, Elapsed, CR);
    printf("%s%srate%s %s%s%.1f%%%s\n",
        BD, C245, CR, BD, C226, Rate, CR);

    PrintLine(Width);
    printf("\n");
}

static void ExportResults(ProxyList *PL, const char *Filename, FilterMode Filter, int Verbose) {
    FILE *Fp = fopen(Filename, "w");
    if (!Fp) {
        fprintf(stderr, "  %s%s[ERR]%s Cannot write: %s\n", BD, C196, CR, Filename);
        return;
    }

    time_t Now = time(NULL);
    struct tm *Tm = localtime(&Now);
    char TBuf[64];
    strftime(TBuf, sizeof(TBuf), "%Y-%m-%d %H:%M:%S", Tm);

    fprintf(Fp, "# HTONSpider v%s  |  %s\n", VersionString, TBuf);
    fprintf(Fp, "# Total: %d  Alive: %d  Dead: %d\n#\n", PL->Count, AliveCount, DeadCount);

    if (Filter != FilterDead) {
        fprintf(Fp, "# -- ALIVE --\n");
        for (int i = 0; i < PL->Count; i++) {
            ProxyEntry *E = &PL->Entries[i];
            if (E->Status != StatusAlive) continue;
            if (Verbose)
                fprintf(Fp, "%s:%d  # %s  %ldms\n", E->Host, E->Port, ProtoName(E->Proto), E->Latency);
            else
                fprintf(Fp, "%s:%d\n", E->Host, E->Port);
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
    printf("  %s%s[✓]%s Saved to %s%s%s%s\n\n", BD, C82, CR, BD, C87, Filename, CR);
}

static ProxyProto ParseProto(const char *S) {
    if (strcasecmp(S, "socks5") == 0) return ProtoSocks5;
    if (strcasecmp(S, "socks4") == 0) return ProtoSocks4;
    if (strcasecmp(S, "http")   == 0) return ProtoHTTP;
    if (strcasecmp(S, "auto")   == 0) return ProtoAuto;
    fprintf(stderr, "  %s%s[ERR]%s Unknown protocol: %s (http|socks4|socks5|auto)\n",
        BD, C196, CR, S);
    exit(1);
}

static void ParseArgs(int Argc, char **Argv, Config *Cfg) {
    memset(Cfg, 0, sizeof(Config));
    strncpy(Cfg->ExportFile, DefaultExport, sizeof(Cfg->ExportFile) - 1);
    Cfg->Port    = DefaultPort;
    Cfg->Timeout = DefaultTimeout;
    Cfg->Threads = DefaultThreads;
    Cfg->Filter  = FilterNone;
    Cfg->Proto   = ProtoAuto;

    for (int i = 1; i < Argc; i++) {
        if      (strcmp(Argv[i], "-h") == 0) { Cfg->HelpRequested = 1; }
        else if (strcmp(Argv[i], "-E") == 0) { Cfg->ExportEnabled = 1; }
        else if (strcmp(Argv[i], "-v") == 0) { Cfg->Verbose       = 1; }
        else if (strcmp(Argv[i], "-s") == 0 && i + 1 < Argc) {
            strncpy(Cfg->Source, Argv[++i], sizeof(Cfg->Source) - 1);
            Cfg->HasSource = 1;
        }
        else if (strcmp(Argv[i], "-L") == 0 && i + 1 < Argc) {
            strncpy(Cfg->LoadFile, Argv[++i], sizeof(Cfg->LoadFile) - 1);
            Cfg->HasLoadFile = 1;
        }
        else if (strcmp(Argv[i], "-p") == 0 && i + 1 < Argc) {
            Cfg->Port = atoi(Argv[++i]);
            if (Cfg->Port <= 0 || Cfg->Port > 65535) {
                fprintf(stderr, "  %s%s[ERR]%s Invalid port\n", BD, C196, CR);
                exit(1);
            }
        }
        else if (strcmp(Argv[i], "-e") == 0 && i + 1 < Argc) {
            strncpy(Cfg->ExportFile, Argv[++i], sizeof(Cfg->ExportFile) - 1);
            Cfg->ExportEnabled = 1;
        }
        else if (strcmp(Argv[i], "-F") == 0 && i + 1 < Argc) {
            i++;
            if      (strcmp(Argv[i], "alive") == 0) Cfg->Filter = FilterAlive;
            else if (strcmp(Argv[i], "dead")  == 0) Cfg->Filter = FilterDead;
            else {
                fprintf(stderr, "  %s%s[ERR]%s Invalid filter (alive|dead)\n", BD, C196, CR);
                exit(1);
            }
        }
        else if (strcmp(Argv[i], "-t") == 0 && i + 1 < Argc) {
            Cfg->Timeout = atoi(Argv[++i]);
            if (Cfg->Timeout <= 0) {
                fprintf(stderr, "  %s%s[ERR]%s Invalid timeout\n", BD, C196, CR);
                exit(1);
            }
        }
        else if (strcmp(Argv[i], "-T") == 0 && i + 1 < Argc) {
            Cfg->Threads = atoi(Argv[++i]);
            if (Cfg->Threads <= 0 || Cfg->Threads > 1000) {
                fprintf(stderr, "  %s%s[ERR]%s Thread count must be 1-1000\n", BD, C196, CR);
                exit(1);
            }
        }
        else if (strcmp(Argv[i], "-P") == 0 && i + 1 < Argc) {
            Cfg->Proto = ParseProto(Argv[++i]);
        }
        else {
            fprintf(stderr, "  %s%s[ERR]%s Unknown option: %s  (use -h for help)\n",
                BD, C196, CR, Argv[i]);
            exit(1);
        }
    }
}

int main(int Argc, char **Argv) {
    signal(SIGINT,  SignalHandler);
    signal(SIGTERM, SignalHandler);

    ParseArgs(Argc, Argv, &GlobalConfig);
    PrintBanner();

    if (GlobalConfig.HelpRequested || Argc == 1) {
        PrintHelp(Argv[0]);
        return 0;
    }

    if (!GlobalConfig.HasSource && !GlobalConfig.HasLoadFile) {
        fprintf(stderr, "  %s%s[ERR]%s No source specified. Use -s <host:port> or -L <file>.\n",
            BD, C196, CR);
        fprintf(stderr, "  %s%s[*]%s  Run with -h for usage.\n\n", BD, C51, CR);
        return 1;
    }

    InitProxyList(&GlobalList);

    if (GlobalConfig.HasSource) {
        char Host[256];
        int  Port;
        ParseHostPort(GlobalConfig.Source, Host, &Port, GlobalConfig.Port);
        AddProxy(&GlobalList, Host, Port, GlobalConfig.Proto);
        printf("  %s%s[+]%s Target  %s%s%s:%d%s  proto: %s%s%s%s\n",
            BD, C82, CR,
            BD, C255, Host, Port, CR,
            BD, C226, ProtoName(GlobalConfig.Proto), CR);
    }

    if (GlobalConfig.HasLoadFile) {
        LoadFromFile(&GlobalList, GlobalConfig.LoadFile,
                     GlobalConfig.Port, GlobalConfig.Proto);
    }

    if (GlobalList.Count == 0) {
        fprintf(stderr, "  %s%s[ERR]%s No proxies to check.\n\n", BD, C196, CR);
        FreeProxyList(&GlobalList);
        return 1;
    }

    RunChecks(&GlobalList, GlobalConfig.Timeout, GlobalConfig.Threads, GlobalConfig.Proto);
    PrintResults(&GlobalList, GlobalConfig.Filter, GlobalConfig.Verbose);

    if (GlobalConfig.ExportEnabled) {
        ExportResults(&GlobalList, GlobalConfig.ExportFile,
                      GlobalConfig.Filter, GlobalConfig.Verbose);
    }

    FreeProxyList(&GlobalList);
    return 0;
}
