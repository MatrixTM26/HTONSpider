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
#define VersionStr      "3.1.0"
#define TestHost        "google.com"
#define TestPort        80
#define Socks4Ver       0x04
#define Socks5Ver       0x05
#define PingCount       4
#define DnsTimeout      5
#define TraceMaxHops    30

typedef enum { ProtoHTTP=0, ProtoSocks4=1, ProtoSocks5=2, ProtoAuto=3 }  ProxyProto;
typedef enum { StatusUnknown=0, StatusAlive=1, StatusDead=2 }             ProxyStatus;
typedef enum { FilterNone=0, FilterAlive=1, FilterDead=2 }                FilterMode;

typedef struct { char Host[256]; int Port; ProxyStatus Status; ProxyProto Proto; long Latency; } ProxyEntry;
typedef struct { ProxyEntry *Entries; int Count; int Capacity; pthread_mutex_t Lock; } ProxyList;
typedef struct { ProxyList *List; int Index; int Timeout; ProxyProto Proto; } WorkerArgs;
typedef struct {
    char Source[256]; char ExportFile[256]; char LoadFile[256];
    int Port, Timeout, Threads, ExportEnabled, HelpRequested, HasLoadFile, HasSource, Verbose;
    FilterMode Filter; ProxyProto Proto;
} ProxyConfig;
typedef struct { int Open; long Latency; char Service[32]; char Banner[256]; } PortResult;

static ProxyList       GlobalList;
static ProxyConfig     GlobalPCfg;
static volatile int    DoneCount=0, AliveCount=0, DeadCount=0, Running=1;
static pthread_mutex_t DoneLock = PTHREAD_MUTEX_INITIALIZER;
static time_t          StartTime;

static const char *CR   = "\033[0m";
static const char *CBlue  = "\033[34m";
static const char *CGreen = "\033[32m";
static const char *CRed   = "\033[31m";
static const char *CWhite = "\033[97m";
static const char *CDim   = "\033[2m";




static const char *BD   = "\033[1m";


static void SigHandler(int S) { (void)S; Running=0; }

static long GetMs() {
    struct timeval T; gettimeofday(&T, NULL);
    return (long)(T.tv_sec*1000 + T.tv_usec/1000);
}


static void PrintBanner() {
    printf("\n%s%s", CBlue, BD);
    printf("  ██╗  ██╗████████╗ ██████╗ ███╗   ██╗\n");
    printf("  ██║  ██║╚══██╔══╝██╔═══██╗████╗  ██║\n");
    printf("  ███████║   ██║   ██║   ██║██╔██╗ ██║\n");
    printf("  ██╔══██║   ██║   ██║   ██║██║╚██╗██║\n");
    printf("  ██║  ██║   ██║   ╚██████╔╝██║ ╚████║\n");
    printf("  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝\n%s", CR);
    printf("  %s%sSPIDER%s  %s%sNetwork Intelligence Toolkit  ·  v%s%s\n",
        CDim, BD, CR, CDim, BD, VersionStr, CR);
    printf("  %s%s────────────────────────────────────────────────%s\n\n", CDim, BD, CR);
}

static void PrintMainHelp(const char *P) {
    PrintBanner();
    printf("  %s%sUSAGE%s\n  %s%s%s <module> [options]%s\n\n", BD, CWhite, CR, BD, CBlue, P, CR);
    printf("  %s%sMODULES%s\n", BD, CDim, CR);
    printf("  %s%sproxy%s    HTTP/SOCKS4/SOCKS5 checker, auto-detect, bulk, export\n",  BD, CBlue,  CR);
    printf("  %s%sscan%s     TCP port scanner, banner grab, service detect\n",           BD, CWhite, CR);
    printf("  %s%sping%s     TCP ping, RTT stats, jitter, packet loss, TX/RX info\n",    BD, CGreen,  CR);
    printf("  %s%strace%s    Traceroute, hop RTT, reverse DNS, AS info\n",               BD, CBlue, CR);
    printf("  %s%sdns%s      Full DNS: A/AAAA/MX/NS/TXT/CNAME/SOA/PTR, custom server\n",BD, CDim, CR);
    printf("  %s%swhois%s    WHOIS IP/domain, multi-server fallback\n",                  BD, CWhite,  CR);
    printf("  %s%shttp%s     HTTP/HTTPS inspector, headers, TLS info, redirect chain\n", BD, CBlue,  CR);
    printf("  %s%sifinfo%s   Interfaces: IP/mask/MTU/flags/MAC/TX/RX/errors\n",         BD, CBlue,  CR);
    printf("  %s%sbanner%s   Raw TCP/UDP banner grab, hex dump, custom payload\n",       BD, CGreen,  CR);
    printf("  %s%ssubnet%s   Subnet calc: range, broadcast, wildcard, class, CIDR\n",   BD, CWhite, CR);
    printf("  %s%sip%s       Public IP info, GeoIP, ASN, org, timezone\n",            BD, CBlue,  CR);
    printf("  %s%ssub%s      Subdomain discovery, DNS bruteforce + IP resolve\n",   BD, CGreen, CR);
    printf("  %s%sdir%s      Web directory discovery, status codes, depth crawl\n\n",BD, CGreen, CR);
    printf("  %s%s%s <module> -h%s  for module help\n\n", CDim, BD, P, CR);
}

static int ResolveToAddr(const char *Host, struct sockaddr_in *Out) {
    struct addrinfo Hints, *Res;
    memset(&Hints,0,sizeof(Hints)); Hints.ai_family=AF_INET;
    if (getaddrinfo(Host,NULL,&Hints,&Res)!=0) return -1;
    *Out = *(struct sockaddr_in*)Res->ai_addr;
    freeaddrinfo(Res); return 0;
}

static int ResolveStr(const char *Host, char *Out, size_t Len) {
    struct sockaddr_in SA;
    if (ResolveToAddr(Host,&SA)<0) return -1;
    inet_ntop(AF_INET,&SA.sin_addr,Out,(socklen_t)Len); return 0;
}

static int ReverseResolve(const char *IP, char *Out, size_t Len) {
    struct sockaddr_in SA; memset(&SA,0,sizeof(SA));
    SA.sin_family=AF_INET; inet_pton(AF_INET,IP,&SA.sin_addr);
    return getnameinfo((struct sockaddr*)&SA,sizeof(SA),Out,(socklen_t)Len,NULL,0,0);
}

static const char *KnownService(int Port) {
    switch(Port) {
        case 21: return "FTP";     case 22: return "SSH";      case 23: return "Telnet";
        case 25: return "SMTP";    case 53: return "DNS";      case 80: return "HTTP";
        case 110:return "POP3";    case 143:return "IMAP";     case 443:return "HTTPS";
        case 445:return "SMB";     case 465:return "SMTPS";    case 587:return "SMTP";
        case 993:return "IMAPS";   case 995:return "POP3S";    case 1080:return "SOCKS";
        case 1194:return "OpenVPN";case 1433:return "MSSQL";   case 3306:return "MySQL";
        case 3389:return "RDP";    case 5432:return "PgSQL";   case 5900:return "VNC";
        case 6379:return "Redis";  case 8080:return "HTTP-Alt";case 8443:return "HTTPS-Alt";
        case 8888:return "HTTP-Alt";case 9200:return "ElasticS";case 27017:return "MongoDB";
        default:  return "";
    }
}

static const char *LatCol(long Ms) {
    if (Ms<100)  return "\033[38;5;82m";
    if (Ms<300)  return "\033[38;5;118m";
    if (Ms<600)  return "\033[38;5;226m";
    if (Ms<1200) return "\033[38;5;214m";
    return "\033[38;5;196m";
}

static int TcpConnect(const char *Host, int Port, int Tsec, long *OL) {
    struct addrinfo Hints, *Res=NULL; char PS[16];
    memset(&Hints,0,sizeof(Hints)); Hints.ai_family=AF_UNSPEC; Hints.ai_socktype=SOCK_STREAM;
    snprintf(PS,sizeof(PS),"%d",Port);
    if (getaddrinfo(Host,PS,&Hints,&Res)!=0) return -1;
    int Fd=socket(Res->ai_family,Res->ai_socktype,Res->ai_protocol);
    if (Fd<0) { freeaddrinfo(Res); return -1; }
    fcntl(Fd,F_SETFL,fcntl(Fd,F_GETFL,0)|O_NONBLOCK);
    long T0=GetMs(); connect(Fd,Res->ai_addr,Res->ai_addrlen); freeaddrinfo(Res);
    fd_set W; struct timeval Tv={Tsec,0}; FD_ZERO(&W); FD_SET(Fd,&W);
    if (select(Fd+1,NULL,&W,NULL,&Tv)<=0) { close(Fd); return -1; }
    int E=0; socklen_t L=sizeof(E); getsockopt(Fd,SOL_SOCKET,SO_ERROR,&E,&L);
    if (E!=0) { close(Fd); return -1; }
    if (OL) *OL = GetMs() - T0;
    return Fd;
}

static int SendAll(int Fd, const unsigned char *B, int L) {
    int S=0; while(S<L){int N=(int)send(Fd,B+S,L-S,0);if(N<=0)return -1;S+=N;} return 0;
}

static int RecvExact(int Fd, unsigned char *B, int L, int Ts) {
    int G=0;
    while(G<L){
        fd_set R; struct timeval Tv={Ts,0}; FD_ZERO(&R); FD_SET(Fd,&R);
        if (select(Fd+1,&R,NULL,NULL,&Tv)<=0) return -1;
        int N=(int)recv(Fd,B+G,L-G,0); if(N<=0) return -1; G+=N;
    } return 0;
}

static int ProbeSocks5(int Fd, int Ts) {
    unsigned char H[3]={Socks5Ver,0x01,0x00};
    if (SendAll(Fd,H,3)<0) return 0;
    unsigned char HR[2]; if (RecvExact(Fd,HR,2,Ts)<0) return 0;
    if (HR[0]!=Socks5Ver||HR[1]!=0x00) return 0;
    size_t HL=strlen(TestHost); unsigned char Rq[300]; int I=0;
    Rq[I++]=Socks5Ver;Rq[I++]=0x01;Rq[I++]=0x00;Rq[I++]=0x03;
    Rq[I++]=(unsigned char)HL; memcpy(&Rq[I],TestHost,HL); I+=(int)HL;
    Rq[I++]=(TestPort>>8)&0xFF; Rq[I++]=TestPort&0xFF;
    if (SendAll(Fd,Rq,I)<0) return 0;
    unsigned char ConnResp[10]; if (RecvExact(Fd,ConnResp,10,Ts)<0) return 0;
    return (ConnResp[0]==Socks5Ver&&ConnResp[1]==0x00)?1:0;
}

static int ProbeSocks4(int Fd, int Ts) {
    struct addrinfo Hints,*Res; memset(&Hints,0,sizeof(Hints)); Hints.ai_family=AF_INET;
    if (getaddrinfo(TestHost,NULL,&Hints,&Res)!=0) return 0;
    struct in_addr Tgt=((struct sockaddr_in*)Res->ai_addr)->sin_addr; freeaddrinfo(Res);
    unsigned char Rq[9];
    Rq[0]=Socks4Ver;Rq[1]=0x01;Rq[2]=(TestPort>>8)&0xFF;Rq[3]=TestPort&0xFF;
    memcpy(&Rq[4],&Tgt.s_addr,4);Rq[8]=0x00;
    if (SendAll(Fd,Rq,9)<0) return 0;
    unsigned char Rs[8]; if (RecvExact(Fd,Rs,8,Ts)<0) return 0;
    return (Rs[0]==0x00&&Rs[1]==0x5A)?1:0;
}

static int ProbeHTTP(int Fd, int Ts) {
    char Rq[512];
    snprintf(Rq,sizeof(Rq),"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
        TestHost,TestPort,TestHost,TestPort);
    if (SendAll(Fd,(unsigned char*)Rq,(int)strlen(Rq))<0) return 0;
    unsigned char Rs[256]; memset(Rs,0,sizeof(Rs));
    fd_set R; struct timeval Tv={Ts,0}; FD_ZERO(&R); FD_SET(Fd,&R);
    if (select(Fd+1,&R,NULL,NULL,&Tv)<=0) return 0;
    int N=(int)recv(Fd,Rs,sizeof(Rs)-1,0); if (N<8) return 0;
    return (strstr((char*)Rs,"200")||strstr((char*)Rs,"HTTP"))?1:0;
}

static ProxyStatus RunProxyCheck(const char *H, int P, int Ts,
                                  long *OL, ProxyProto In, ProxyProto *Out) {
    long Lat=0;
    if (In!=ProtoAuto) {
        int Fd=TcpConnect(H,P,Ts,&Lat); if (Fd<0) return StatusDead;
        int Ok=0;
        switch(In){case ProtoSocks5:Ok=ProbeSocks5(Fd,Ts);break;case ProtoSocks4:Ok=ProbeSocks4(Fd,Ts);break;default:Ok=ProbeHTTP(Fd,Ts);}
        close(Fd);
        if (Ok){if(OL)*OL=Lat;if(Out)*Out=In;} return Ok?StatusAlive:StatusDead;
    }
    int Fd=TcpConnect(H,P,Ts,&Lat); if (Fd<0) return StatusDead;
    if (ProbeSocks5(Fd,Ts)){close(Fd);if(OL)*OL=Lat;if(Out)*Out=ProtoSocks5;return StatusAlive;}
    shutdown(Fd,SHUT_RDWR);close(Fd);
    Fd=TcpConnect(H,P,Ts,&Lat); if (Fd<0) return StatusDead;
    if (ProbeSocks4(Fd,Ts)){close(Fd);if(OL)*OL=Lat;if(Out)*Out=ProtoSocks4;return StatusAlive;}
    shutdown(Fd,SHUT_RDWR);close(Fd);
    Fd=TcpConnect(H,P,Ts,&Lat); if (Fd<0) return StatusDead;
    if (ProbeHTTP(Fd,Ts)){close(Fd);if(OL)*OL=Lat;if(Out)*Out=ProtoHTTP;return StatusAlive;}
    close(Fd); return StatusDead;
}

static void *ProxyWorker(void *Arg) {
    WorkerArgs *WA=(WorkerArgs*)Arg; ProxyEntry *E=&WA->List->Entries[WA->Index];
    long Lat=0; ProxyProto Det=WA->Proto;
    E->Status=RunProxyCheck(E->Host,E->Port,WA->Timeout,&Lat,WA->Proto,&Det);
    E->Latency=Lat; E->Proto=(E->Status==StatusAlive)?Det:WA->Proto;
    pthread_mutex_lock(&DoneLock); DoneCount++;
    if (E->Status==StatusAlive) AliveCount++; else DeadCount++;
    pthread_mutex_unlock(&DoneLock); free(WA); return NULL;
}

static void ParseHostPort(const char *In, char *OH, int *OP, int Def) {
    const char *C=strrchr(In,':');
    if (C){size_t L=(size_t)(C-In);if(L>=256)L=255;strncpy(OH,In,L);OH[L]='\0';*OP=atoi(C+1);if(*OP<=0||*OP>65535)*OP=Def;}
    else{strncpy(OH,In,255);OH[255]='\0';*OP=Def;}
}

static void TrimLine(char *S) {
    size_t L=strlen(S);
    while(L>0&&(S[L-1]=='\n'||S[L-1]=='\r'||S[L-1]==' '))S[--L]='\0';
    char *P=S; while(*P&&(*P==' '||*P=='\t'))P++; if(P!=S)memmove(S,P,strlen(P)+1);
}

static void InitProxyList(ProxyList *PL) {
    PL->Entries=(ProxyEntry*)malloc(sizeof(ProxyEntry)*MaxProxies);
    PL->Count=0; PL->Capacity=MaxProxies; pthread_mutex_init(&PL->Lock,NULL);
}

static void FreeProxyList(ProxyList *PL) { free(PL->Entries); pthread_mutex_destroy(&PL->Lock); }

static void AddProxy(ProxyList *PL, const char *H, int P, ProxyProto Pr) {
    pthread_mutex_lock(&PL->Lock);
    if (PL->Count<PL->Capacity){ProxyEntry *E=&PL->Entries[PL->Count++];strncpy(E->Host,H,255);E->Host[255]='\0';E->Port=P;E->Status=StatusUnknown;E->Proto=Pr;E->Latency=0;}
    pthread_mutex_unlock(&PL->Lock);
}

static void LoadProxiesFromFile(ProxyList *PL, const char *Fn, int Def, ProxyProto Pr) {
    FILE *Fp=fopen(Fn,"r");
    if (!Fp){fprintf(stderr,"  %s%s[ERR]%s Cannot open: %s\n\n",BD,CRed,CR,Fn);exit(1);}
    char Line[512]; int N=0;
    while(fgets(Line,sizeof(Line),Fp)){TrimLine(Line);if(!Line[0]||Line[0]=='#')continue;char H[256];int P;ParseHostPort(Line,H,&P,Def);AddProxy(PL,H,P,Pr);N++;}
    fclose(Fp);
    printf("  %s%s[+]%s Loaded %s%s%d%s entr%s from %s%s%s%s\n",BD,CGreen,CR,BD,CWhite,N,CR,N==1?"y":"ies",BD,CWhite,Fn,CR);
}

static const char *ProtoTag(ProxyProto P){switch(P){case ProtoHTTP:return "HTTP  ";case ProtoSocks4:return "SOCKS4";case ProtoSocks5:return "SOCKS5";default:return "AUTO  ";}}
static const char *ProtoCol(ProxyProto P){switch(P){case ProtoHTTP:return "\033[38;5;39m";case ProtoSocks4:return "\033[38;5;201m";case ProtoSocks5:return "\033[38;5;226m";default:return "\033[38;5;245m";}}

static void DrawProxyProgress(int Done, int Total, int Alive, int Dead, int Active) {
    int BW=28,Filled=(Total>0)?(Done*BW/Total):0;
    float Pct=(Total>0)?((float)Done*100.0f/(float)Total):0.0f;
    time_t El=time(NULL)-StartTime; int Rem=0;
    if (Done>0&&El>0){float R=(float)Done/(float)El;Rem=(R>0.0f)?(int)((Total-Done)/R):0;}
    printf("\r  %s%s[%s",BD,CDim,CR);
    for (int i=0;i<BW;i++) printf(i<Filled?"%s%s█%s":"%s▒%s",(i<Filled?BD:""),CBlue,CR);
    printf("%s%s]%s %s%s%5.1f%%%s  %s%s%d/%d%s  %s%s+%d%s  %s%s-%d%s  %s%s~%ds%s  %s%s[%dT]%s",
        BD,CDim,CR,BD,CWhite,Pct,CR,CDim,BD,Done,Total,CR,CGreen,BD,Alive,CR,CRed,BD,Dead,CR,CDim,BD,Rem,CR,CBlue,BD,Active,CR);
    fflush(stdout);
}

static void RunProxyChecks(ProxyList *PL, int Ts, int MaxT, ProxyProto Proto) {
    int Total=PL->Count,Active=0,Launched=0; StartTime=time(NULL);
    printf("\n  %s%s[*]%s %s%s%d%s proxies  %sproto:%s %s%s%s%s  %sthreads:%s %s%s%d%s  %stimeout:%s %s%s%ds%s\n\n",
        BD,CBlue,CR,BD,CWhite,Total,CR,CDim,CR,BD,ProtoCol(Proto),ProtoTag(Proto),CR,CDim,CR,BD,CBlue,MaxT,CR,CDim,CR,BD,CDim,Ts,CR);
    pthread_t *Thr=(pthread_t*)malloc(sizeof(pthread_t)*Total);
    while(Running&&(Launched<Total||Active>0)){
        while(Active<MaxT&&Launched<Total&&Running){
            WorkerArgs *WA=(WorkerArgs*)malloc(sizeof(WorkerArgs));
            WA->List=PL;WA->Index=Launched;WA->Timeout=Ts;WA->Proto=Proto;
            pthread_create(&Thr[Launched],NULL,ProxyWorker,WA);Launched++;Active++;
        }
        usleep(5000);
        pthread_mutex_lock(&DoneLock);int D=DoneCount,A=AliveCount,X=DeadCount;pthread_mutex_unlock(&DoneLock);
        Active=Launched-D; DrawProxyProgress(D,Total,A,X,Active);
    }
    for(int i=0;i<Launched;i++) pthread_join(Thr[i],NULL);
    free(Thr); DrawProxyProgress(Total,Total,AliveCount,DeadCount,0); printf("\n");
}

static void PrintProxyResults(ProxyList *PL, FilterMode Filter, int Verbose) {
    printf("\n"); printf("\n");
    printf("  %s%s  PROXY RESULTS%s\n",BD,CWhite,CR);
    printf("\n");printf("\n");
    int Shown=0;
    for(int i=0;i<PL->Count;i++){
        ProxyEntry *E=&PL->Entries[i];
        if(Filter==FilterAlive&&E->Status!=StatusAlive)continue;
        if(Filter==FilterDead&&E->Status!=StatusDead)continue;
        if(E->Status==StatusAlive){
            char Addr[300];snprintf(Addr,sizeof(Addr),"%s:%d",E->Host,E->Port);
            printf("  %s%s ALIVE %s  %s%s%s%-6s%s  %s%s%-42s%s",BD,CGreen,CR,BD,ProtoCol(E->Proto),BD,ProtoTag(E->Proto),CR,BD,CWhite,Addr,CR);
            if(Verbose)printf("  %s%s%ldms%s",LatCol(E->Latency),BD,E->Latency,CR);
        } else {
            printf("  %s%s DEAD  %s  %s%s%-6s%s  %s%s%s:%d%s",BD,CRed,CR,BD,CDim,ProtoTag(E->Proto),CR,CDim,BD,E->Host,E->Port,CR);
        }
        printf("\n");Shown++;
    }
    if(!Shown)printf("  %s%s  No entries match the filter.%s\n",BD,CDim,CR);
    printf("\n");printf("\n");
    time_t El=time(NULL)-StartTime;
    float Rate=(PL->Count>0)?((float)AliveCount*100.0f/(float)PL->Count):0.0f;
    printf("  %s%stotal%s %s%s%d%s  %s%salive%s %s%s%d%s  %s%sdead%s %s%s%d%s  %s%selapsed%s %s%s%lds%s  %s%srate%s %s%s%.1f%%%s\n",
        BD,CDim,CR,BD,CWhite,PL->Count,CR,BD,CGreen,CR,BD,CGreen,AliveCount,CR,BD,CRed,CR,BD,CRed,DeadCount,CR,BD,CDim,CR,BD,CDim,El,CR,BD,CDim,CR,BD,CWhite,Rate,CR);
    printf("\n");printf("\n");
}

static void ExportProxyResults(ProxyList *PL, const char *Fn, FilterMode Filter, int Verbose) {
    FILE *Fp=fopen(Fn,"w"); if(!Fp){fprintf(stderr,"  %s%s[ERR]%s Cannot write: %s\n",BD,CRed,CR,Fn);return;}
    time_t Now=time(NULL);struct tm *Tm=localtime(&Now);char TB[64];strftime(TB,sizeof(TB),"%Y-%m-%d %H:%M:%S",Tm);
    fprintf(Fp,"# HTONSpider v%s  |  %s\n# Total: %d  Alive: %d  Dead: %d\n#\n",VersionStr,TB,PL->Count,AliveCount,DeadCount);
    if(Filter!=FilterDead){fprintf(Fp,"# -- ALIVE --\n");for(int i=0;i<PL->Count;i++){ProxyEntry *E=&PL->Entries[i];if(E->Status!=StatusAlive)continue;if(Verbose)fprintf(Fp,"%s:%d  # %s  %ldms\n",E->Host,E->Port,ProtoTag(E->Proto),E->Latency);else fprintf(Fp,"%s:%d\n",E->Host,E->Port);}}
    if(Filter!=FilterAlive){fprintf(Fp,"#\n# -- DEAD --\n");for(int i=0;i<PL->Count;i++){ProxyEntry *E=&PL->Entries[i];if(E->Status!=StatusDead)continue;fprintf(Fp,"%s:%d\n",E->Host,E->Port);}}
    fclose(Fp); printf("  %s%s[✓]%s Saved to %s%s%s%s\n\n",BD,CGreen,CR,BD,CWhite,Fn,CR);
}

static ProxyProto ParseProto(const char *S) {
    if (strcasecmp(S,"socks5")==0) return ProtoSocks5;
    if (strcasecmp(S,"socks4")==0) return ProtoSocks4;
    if (strcasecmp(S,"http"  )==0) return ProtoHTTP;
    if (strcasecmp(S,"auto"  )==0) return ProtoAuto;
    fprintf(stderr,"  %s%s[ERR]%s Unknown protocol: %s\n",BD,CRed,CR,S);
    exit(1);
}

static void ModuleProxy(int Argc, char **Argv) {
    memset(&GlobalPCfg,0,sizeof(GlobalPCfg));
    strncpy(GlobalPCfg.ExportFile,DefaultExport,sizeof(GlobalPCfg.ExportFile)-1);
    GlobalPCfg.Port=DefaultPort;GlobalPCfg.Timeout=DefaultTimeout;GlobalPCfg.Threads=DefaultThreads;
    GlobalPCfg.Filter=FilterNone;GlobalPCfg.Proto=ProtoAuto;
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {GlobalPCfg.HelpRequested=1;}
        else if(!strcmp(Argv[i],"-E"))           {GlobalPCfg.ExportEnabled=1;}
        else if(!strcmp(Argv[i],"-v"))           {GlobalPCfg.Verbose=1;}
        else if(!strcmp(Argv[i],"-s")&&i+1<Argc){strncpy(GlobalPCfg.Source,    Argv[++i],sizeof(GlobalPCfg.Source)-1);    GlobalPCfg.HasSource=1;}
        else if(!strcmp(Argv[i],"-L")&&i+1<Argc){strncpy(GlobalPCfg.LoadFile,  Argv[++i],sizeof(GlobalPCfg.LoadFile)-1);  GlobalPCfg.HasLoadFile=1;}
        else if(!strcmp(Argv[i],"-e")&&i+1<Argc){strncpy(GlobalPCfg.ExportFile,Argv[++i],sizeof(GlobalPCfg.ExportFile)-1);GlobalPCfg.ExportEnabled=1;}
        else if(!strcmp(Argv[i],"-P")&&i+1<Argc){GlobalPCfg.Proto=ParseProto(Argv[++i]);}
        else if(!strcmp(Argv[i],"-p")&&i+1<Argc){GlobalPCfg.Port=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){GlobalPCfg.Timeout=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-T")&&i+1<Argc){GlobalPCfg.Threads=atoi(Argv[++i]);if(GlobalPCfg.Threads>1000)GlobalPCfg.Threads=1000;}
        else if(!strcmp(Argv[i],"-F")&&i+1<Argc){i++;if(!strcmp(Argv[i],"alive"))GlobalPCfg.Filter=FilterAlive;else if(!strcmp(Argv[i],"dead"))GlobalPCfg.Filter=FilterDead;}
    }
    if(GlobalPCfg.HelpRequested){
        printf("  %s%sproxy%s  HTTP/SOCKS4/SOCKS5 checker\n\n",BD,CBlue,CR);
        printf("  %s%s-s%s %s<host:port>%s     Single proxy\n",BD,CWhite,CR,CWhite,CR);
        printf("  %s%s-L%s %s<file>%s          Proxy list file\n",BD,CWhite,CR,CWhite,CR);
        printf("  %s%s-P%s %s<proto>%s         http|socks4|socks5|auto (def: auto)\n",BD,CWhite,CR,CWhite,CR);
        printf("  %s%s-p%s %s<port>%s          Default port (def: %d)\n",BD,CWhite,CR,CWhite,CR,DefaultPort);
        printf("  %s%s-t%s %s<sec>%s           Timeout (def: %d)\n",BD,CWhite,CR,CWhite,CR,DefaultTimeout);
        printf("  %s%s-T%s %s<threads>%s       Threads (def: %d)\n",BD,CWhite,CR,CWhite,CR,DefaultThreads);
        printf("  %s%s-E%s                 Export to checked.txt\n",BD,CWhite,CR);
        printf("  %s%s-e%s %s<file>%s          Custom export file\n",BD,CWhite,CR,CWhite,CR);
        printf("  %s%s-F%s %s<alive|dead>%s    Filter output\n",BD,CWhite,CR,CWhite,CR);
        printf("  %s%s-v%s                 Verbose (show latency)\n\n",BD,CWhite,CR);
        return;
    }
    if(!GlobalPCfg.HasSource&&!GlobalPCfg.HasLoadFile){fprintf(stderr,"  %s%s[ERR]%s Use -s or -L\n\n",BD,CRed,CR);return;}
    InitProxyList(&GlobalList);
    if(GlobalPCfg.HasSource){char H[256];int P;ParseHostPort(GlobalPCfg.Source,H,&P,GlobalPCfg.Port);AddProxy(&GlobalList,H,P,GlobalPCfg.Proto);printf("  %s%s[+]%s %s%s%s:%d%s  proto: %s%s%s%s\n",BD,CGreen,CR,BD,CWhite,H,P,CR,BD,CWhite,ProtoTag(GlobalPCfg.Proto),CR);}
    if(GlobalPCfg.HasLoadFile)LoadProxiesFromFile(&GlobalList,GlobalPCfg.LoadFile,GlobalPCfg.Port,GlobalPCfg.Proto);
    if(!GlobalList.Count){fprintf(stderr,"  %s%s[ERR]%s No proxies.\n\n",BD,CRed,CR);FreeProxyList(&GlobalList);return;}
    RunProxyChecks(&GlobalList,GlobalPCfg.Timeout,GlobalPCfg.Threads,GlobalPCfg.Proto);
    PrintProxyResults(&GlobalList,GlobalPCfg.Filter,GlobalPCfg.Verbose);
    if(GlobalPCfg.ExportEnabled)ExportProxyResults(&GlobalList,GlobalPCfg.ExportFile,GlobalPCfg.Filter,GlobalPCfg.Verbose);
    FreeProxyList(&GlobalList);
}

static volatile int ScanDone=0;
static pthread_mutex_t ScanLock=PTHREAD_MUTEX_INITIALIZER;
static PortResult ScanResults[65536];

typedef struct { char Host[256]; int Port; int Timeout; int Verbose; } ScanWorkerArg;

static void *ScanWorker(void *Arg) {
    ScanWorkerArg *SA=(ScanWorkerArg*)Arg; int Port=SA->Port; long Lat=0;
    int Fd=TcpConnect(SA->Host,Port,SA->Timeout,&Lat);
    pthread_mutex_lock(&ScanLock); ScanDone++;
    if(Fd>=0){
        ScanResults[Port].Open=1; ScanResults[Port].Latency=Lat;
        const char *Svc=KnownService(Port); strncpy(ScanResults[Port].Service,Svc,sizeof(ScanResults[Port].Service)-1);
        if(SA->Verbose){
            unsigned char Bn[256];memset(Bn,0,sizeof(Bn));
            fd_set R;struct timeval Tv={1,0};FD_ZERO(&R);FD_SET(Fd,&R);
            if(select(Fd+1,&R,NULL,NULL,&Tv)>0)recv(Fd,Bn,sizeof(Bn)-1,0);
            for(int i=0;i<(int)strlen((char*)Bn);i++)if(!isprint(Bn[i])&&Bn[i]!='\n'&&Bn[i]!='\r')Bn[i]='.';
            char *NL=strchr((char*)Bn,'\n');if(NL)*NL='\0';
            char *NR=strchr((char*)Bn,'\r');if(NR)*NR='\0';
            snprintf(ScanResults[Port].Banner, sizeof(ScanResults[Port].Banner), "%s", (char*)Bn);
        }
        close(Fd);
    }
    pthread_mutex_unlock(&ScanLock); free(SA); return NULL;
}

static void ModuleScan(int Argc, char **Argv) {
    char Host[256]={0}; int Start=1,End=1024,Timeout=2,Verbose=0,Threads=300;
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {printf("  %s%sscan%s module\n\n",BD,CWhite,CR);printf("  %s%s-t%s %s<host>%s        Target\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-p%s %s<start[-end]>%s Port range (def: 1-1024)\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-T%s %s<n>%s           Threads (def: 300)\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-w%s %s<sec>%s         Timeout (def: 2)\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-v%s               Banner grab\n\n",BD,CWhite,CR);return;}
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){strncpy(Host,Argv[++i],sizeof(Host)-1);}
        else if(!strcmp(Argv[i],"-p")&&i+1<Argc){char *Rng=Argv[++i];char *D=strchr(Rng,'-');if(D){*D='\0';Start=atoi(Rng);End=atoi(D+1);}else{Start=End=atoi(Rng);}}
        else if(!strcmp(Argv[i],"-T")&&i+1<Argc){Threads=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-w")&&i+1<Argc){Timeout=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-v"))           {Verbose=1;}
        else if(Argv[i][0]!='-'&&!Host[0])       {strncpy(Host,Argv[i],sizeof(Host)-1);}
    }
    if(!Host[0]){fprintf(stderr,"  %s%s[ERR]%s No target.\n\n",BD,CRed,CR);return;}
    char IP[64]={0}; ResolveStr(Host,IP,sizeof(IP)); if(!IP[0])snprintf(IP,sizeof(IP),"%s",Host);
    memset(ScanResults,0,sizeof(ScanResults)); ScanDone=0;
    int Total=End-Start+1;
    printf("\n  %s%sPORT SCAN%s  %s%s%s%s  (%s%s%s%s)\n",BD,CWhite,CR,BD,CWhite,Host,CR,CDim,BD,IP,CR);
    printf("  %s%srange%s %s%s%d–%d%s  %s%sthreads%s %s%s%d%s  %s%stimeout%s %s%s%ds%s\n\n",
        BD,CDim,CR,BD,CWhite,Start,End,CR,BD,CDim,CR,BD,CBlue,Threads,CR,BD,CDim,CR,BD,CDim,Timeout,CR);
    ScanWorkerArg SA; memset(&SA,0,sizeof(SA)); snprintf(SA.Host,sizeof(SA.Host),"%s",Host); SA.Timeout=Timeout; SA.Verbose=Verbose;
    pthread_t *Thr=(pthread_t*)malloc(sizeof(pthread_t)*Total);
    int Launched=0,Active=0; time_t T0=time(NULL);
    for(int Port=Start;Port<=End;Port++){
        while(Active>=Threads){usleep(2000);pthread_mutex_lock(&ScanLock);Active=Launched-ScanDone;pthread_mutex_unlock(&ScanLock);}
        ScanWorkerArg *SWA=(ScanWorkerArg*)malloc(sizeof(ScanWorkerArg));*SWA=SA;SWA->Port=Port;
        pthread_create(&Thr[Launched],NULL,ScanWorker,SWA);Launched++;Active++;
        pthread_mutex_lock(&ScanLock);int D=ScanDone;pthread_mutex_unlock(&ScanLock);
        float Pct=(float)D*100.0f/(float)Total;int BW=24;
        printf("\r  %s%s[%s",BD,CDim,CR);
        for(int b=0;b<BW;b++)printf(b<(int)(Pct/100.0f*BW)?"%s%s█%s":"%s▒%s",(b<(int)(Pct/100.0f*BW)?BD:""),CWhite,CR);
        printf("%s%s]%s %s%s%5.1f%%%s  port %s%s%d%s    ",BD,CDim,CR,BD,CWhite,Pct,CR,BD,CWhite,Port,CR);
        fflush(stdout);
    }
    for (int i = 0; i < Launched; i++) pthread_join(Thr[i], NULL);
    free(Thr);
    printf("\r%70s\r","");
    int OpenCount=0;
    printf("\n");
    printf("  %s%s  PORT SCAN RESULTS  —  %s  (%s)%s\n",BD,CWhite,Host,IP,CR);
    printf("\n");printf("\n");
    printf("  %s%s%-7s  %-8s  %-12s  %-8s  %s%s\n\n",BD,CDim,"PORT","STATE","SERVICE","LATENCY",CR,"");
    for(int Port=Start;Port<=End;Port++){
        if (!ScanResults[Port].Open) continue;
        OpenCount++;
        char LS[32]; snprintf(LS,sizeof(LS),"%ldms",ScanResults[Port].Latency);
        const char *Svc=ScanResults[Port].Service[0]?ScanResults[Port].Service:"unknown";
        printf("  %s%s%-7d%s  %s%sOPEN%s    %s%s%-12s%s  %s%s%-8s%s",BD,CGreen,Port,CR,BD,CGreen,CR,BD,CWhite,Svc,CR,LatCol(ScanResults[Port].Latency),BD,LS,CR);
        if(Verbose&&ScanResults[Port].Banner[0])printf("  %s%s%s%s",CDim,BD,ScanResults[Port].Banner,CR);
        printf("\n");
    }
    printf("\n");printf("\n");
    printf("  %s%sopen%s %s%s%d%s  %s%sclosed/filtered%s %s%s%d%s  %s%stime%s %s%s%lds%s\n",
        BD,CGreen,CR,BD,CGreen,OpenCount,CR,BD,CDim,CR,BD,CRed,Total-OpenCount,CR,BD,CDim,CR,BD,CDim,(long)(time(NULL)-T0),CR);
    printf("\n");printf("\n");
}

static void ModulePing(int Argc, char **Argv) {
    char Host[256]={0};
    int Count=PingCount,Interval=1,Timeout=3,TcpPort=80;
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {
            printf("  %s%sping%s module\n\n",BD,CGreen,CR);
            printf("  %s%s-t%s %s<host>%s      Target\n",BD,CWhite,CR,CWhite,CR);
            printf("  %s%s-c%s %s<count>%s     Count (def: 4)\n",BD,CWhite,CR,CWhite,CR);
            printf("  %s%s-i%s %s<sec>%s       Interval (def: 1)\n",BD,CWhite,CR,CWhite,CR);
            printf("  %s%s-w%s %s<sec>%s       Timeout (def: 3)\n",BD,CWhite,CR,CWhite,CR);
            printf("  %s%s-p%s %s<port>%s      TCP port (def: 80)\n\n",BD,CWhite,CR,CWhite,CR);
            return;
        }
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){strncpy(Host,Argv[++i],sizeof(Host)-1);}
        else if(!strcmp(Argv[i],"-c")&&i+1<Argc){Count=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-i")&&i+1<Argc){Interval=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-w")&&i+1<Argc){Timeout=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-p")&&i+1<Argc){TcpPort=atoi(Argv[++i]);}
        else if(Argv[i][0]!='-'&&!Host[0])       {strncpy(Host,Argv[i],sizeof(Host)-1);}
    }
    if(!Host[0]){fprintf(stderr,"  %s%s[ERR]%s No target.\n\n",BD,CRed,CR);return;}

    char IP[64]={0}; ResolveStr(Host,IP,sizeof(IP)); if(!IP[0])snprintf(IP,sizeof(IP),"%s",Host);
    char RevHost[256]={0}; ReverseResolve(IP,RevHost,sizeof(RevHost));

    printf("\n");printf("\n");
    printf("  %s%sPING%s  %s%s%s%s  %s%s(%s)%s  port %s%s%d%s\n",
        BD,CGreen,CR,BD,CWhite,Host,CR,CDim,BD,IP,CR,BD,CWhite,TcpPort,CR);
    if(RevHost[0]&&strcmp(RevHost,IP)!=0&&strcmp(RevHost,Host)!=0)
        printf("  %s%srdns%s    %s%s%s%s\n",BD,CDim,CR,CDim,CDim,RevHost,CR);
    printf("\n");printf("\n");
    printf("  %s%s%-5s  %-22s  %-10s  %-10s  %s%s\n\n",BD,CDim,"SEQ","TARGET","RTT","STATUS",CR,"");

    long Rtts[4096]; int Sent=0,Recv=0;
    long TxBytes=0,RxBytes=0;
    if(Count>4096)Count=4096;
    memset(Rtts,0,sizeof(long)*Count);

    for(int i=0;i<Count&&Running;i++){
        long Lat=0; long T0=GetMs();
        int Fd=TcpConnect(Host,TcpPort,Timeout,&Lat);
        long T1=GetMs()-T0; Sent++;
        TxBytes+=64;

        if(Fd>=0){
            close(Fd); Recv++;
            Rtts[i]=Lat>0?Lat:T1;
            RxBytes+=128;
            const char *LC=LatCol(Rtts[i]);
            char StatusBar[32];
            if(Rtts[i]<100)      snprintf(StatusBar,sizeof(StatusBar),"▓▓▓▓▓");
            else if(Rtts[i]<300) snprintf(StatusBar,sizeof(StatusBar),"▓▓▓▓░");
            else if(Rtts[i]<600) snprintf(StatusBar,sizeof(StatusBar),"▓▓▓░░");
            else if(Rtts[i]<1200)snprintf(StatusBar,sizeof(StatusBar),"▓▓░░░");
            else                 snprintf(StatusBar,sizeof(StatusBar),"▓░░░░");
            printf("  %s%s%-5d%s  %s%s%s:%d%s  %s%-10s%s  %s%s%ldms%s  %s%s%s%s\n",
                BD,CDim,i+1,CR,BD,CWhite,Host,TcpPort,CR,
                LC,StatusBar,CR,
                LC,BD,Rtts[i],CR,
                BD,CGreen,"ALIVE",CR);
        } else {
            printf("  %s%s%-5d%s  %s%s%s:%d%s  %s%-10s%s  %s%s---%s   %s%s%s%s\n",
                BD,CDim,i+1,CR,BD,CWhite,Host,TcpPort,CR,
                CRed,"▒▒▒▒▒",CR,
                CRed,BD,CR,
                BD,CRed,"TIMEOUT",CR);
        }
        if(i<Count-1)sleep((unsigned)Interval);
    }

    long Min=999999,Max=0,Sum=0,SumSq=0;
    int RealRecv=0;
    for(int i=0;i<Count;i++){
        if(!Rtts[i])continue;
        if(Rtts[i]<Min)Min=Rtts[i];
        if(Rtts[i]>Max)Max=Rtts[i];
        Sum+=Rtts[i];SumSq+=Rtts[i]*Rtts[i];RealRecv++;
    }
    long Avg=RealRecv>0?Sum/RealRecv:0;
    double Jitter=0;
    if(RealRecv>1){
        double Variance=(double)SumSq/(double)RealRecv-((double)Sum/(double)RealRecv)*((double)Sum/(double)RealRecv);
        Jitter=sqrt(Variance>0?Variance:0);
    }
    float Loss=(float)(Sent-Recv)*100.0f/(float)Sent;

    printf("\n");printf("\n");
    printf("  %s%s STATISTICS%s\n\n",BD,CWhite,CR);
    printf("  %s%starget%s    %s%s%s%s  %s%s(%s)%s\n",BD,CDim,CR,BD,CWhite,Host,CR,CDim,CDim,IP,CR);
    printf("  %s%sport%s      %s%s%d%s  %s%sprotocol%s %s%sTCP-connect%s\n",BD,CDim,CR,BD,CWhite,TcpPort,CR,BD,CDim,CR,BD,CWhite,CR);
    printf("\n");
    printf("  %s%spackets%s   sent=%s%s%d%s  recv=%s%s%d%s  loss=%s%s%.1f%%%s\n",
        BD,CDim,CR,BD,CWhite,Sent,CR,BD,CGreen,Recv,CR,BD,Loss>0?CRed:CGreen,Loss,CR);
    printf("  %s%sbytes%s     tx=%s%s%ld B%s  rx=%s%s%ld B%s\n",
        BD,CDim,CR,BD,CDim,TxBytes,CR,BD,CGreen,RxBytes,CR);
    printf("\n");
    if(Recv>0){
        printf("  %s%srtt%s       min=%s%s%ldms%s  avg=%s%s%ldms%s  max=%s%s%ldms%s  jitter=%s%s%.1fms%s\n",
            BD,CDim,CR,BD,CGreen,Min,CR,BD,CWhite,Avg,CR,BD,CDim,Max,CR,BD,CBlue,Jitter,CR);
        printf("  %s%squality%s  ",BD,CDim,CR);
        if(Loss==0&&Avg<100)      printf("%s%s EXCELLENT %s  sub-100ms, no loss\n",BD,CGreen,CR);
        else if(Loss==0&&Avg<300) printf("%s%s GOOD      %s  no loss\n",BD,CWhite,CR);
        else if(Loss<5&&Avg<600)  printf("%s%s FAIR      %s  minor loss/latency\n",BD,CDim,CR);
        else                      printf("%s%s POOR      %s  high loss or latency\n",BD,CRed,CR);
    }
    printf("\n");printf("\n");
}

static void ModuleTrace(int Argc, char **Argv) {
    char Host[256]={0}; int MaxHops=TraceMaxHops,Timeout=3,Queries=3;
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {
            printf("  %s%strace%s module\n\n",BD,CBlue,CR);
            printf("  %s%s-t%s %s<host>%s    Target\n",BD,CWhite,CR,CWhite,CR);
            printf("  %s%s-m%s %s<hops>%s    Max hops (def: 30)\n",BD,CWhite,CR,CWhite,CR);
            printf("  %s%s-q%s %s<n>%s       Queries per hop (def: 3)\n",BD,CWhite,CR,CWhite,CR);
            printf("  %s%s-w%s %s<sec>%s     Timeout (def: 3)\n\n",BD,CWhite,CR,CWhite,CR);
            return;
        }
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){strncpy(Host,Argv[++i],sizeof(Host)-1);}
        else if(!strcmp(Argv[i],"-m")&&i+1<Argc){MaxHops=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-q")&&i+1<Argc){Queries=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-w")&&i+1<Argc){Timeout=atoi(Argv[++i]);}
        else if(Argv[i][0]!='-'&&!Host[0])       {strncpy(Host,Argv[i],sizeof(Host)-1);}
    }
    if(!Host[0]){fprintf(stderr,"  %s%s[ERR]%s No target.\n\n",BD,CRed,CR);return;}

    struct sockaddr_in Dest;
    if(ResolveToAddr(Host,&Dest)<0){fprintf(stderr,"  %s%s[ERR]%s Cannot resolve: %s\n\n",BD,CRed,CR,Host);return;}
    char DestIP[64]; inet_ntop(AF_INET,&Dest.sin_addr,DestIP,sizeof(DestIP));

    printf("\n");printf("\n");
    printf("  %s%sTRACEROUTE%s  %s%s%s%s  %s%s(%s)%s  max %s%s%d%s hops  %s%s%d%s queries/hop\n",
        BD,CBlue,CR,BD,CWhite,Host,CR,CDim,BD,DestIP,CR,BD,CWhite,MaxHops,CR,BD,CBlue,Queries,CR);
    printf("\n");printf("\n");
    printf("  %s%s%-4s  %-20s  %-36s  %s%s\n\n",BD,CDim,"HOP","ADDRESS","HOSTNAME","RTT",CR);

    for(int Ttl=1;Ttl<=MaxHops&&Running;Ttl++){
        long Rtts[8]={0}; char HopIP[64]={0}; int Got=0;

        for(int Q=0;Q<Queries&&Q<8;Q++){
            int Sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
            if(Sock<0)continue;
            setsockopt(Sock,IPPROTO_IP,IP_TTL,&Ttl,sizeof(Ttl));
            struct timeval Tv={Timeout,0};
            setsockopt(Sock,SOL_SOCKET,SO_RCVTIMEO,&Tv,sizeof(Tv));
            int RecvSock=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
            if(RecvSock<0){close(Sock);continue;}
            setsockopt(RecvSock,SOL_SOCKET,SO_RCVTIMEO,&Tv,sizeof(Tv));
            Dest.sin_port=htons((uint16_t)(33434+Ttl*Queries+Q));
            unsigned char Payload[32];memset(Payload,0,sizeof(Payload));
            long T0=GetMs();
            sendto(Sock,Payload,sizeof(Payload),0,(struct sockaddr*)&Dest,sizeof(Dest));
            struct sockaddr_in Sender;socklen_t SLen=sizeof(Sender);
            unsigned char Buf[512];
            int N=(int)recvfrom(RecvSock,Buf,sizeof(Buf),0,(struct sockaddr*)&Sender,&SLen);
            long Rtt=GetMs()-T0;
            close(Sock);close(RecvSock);
            if(N>0){
                inet_ntop(AF_INET,&Sender.sin_addr,HopIP,sizeof(HopIP));
                Rtts[Q]=Rtt; Got++;
            }
        }

        if(!Got){
            printf("  %s%s%-4d%s  %s%s*%s\n",BD,CDim,Ttl,CR,BD,CRed,CR);
            continue;
        }

        long RttMin=999999,RttMax=0,RttSum=0;
        for(int Q=0;Q<Queries;Q++){if(Rtts[Q]>0){if(Rtts[Q]<RttMin)RttMin=Rtts[Q];if(Rtts[Q]>RttMax)RttMax=Rtts[Q];RttSum+=Rtts[Q];}}
        long RttAvg=Got>0?RttSum/Got:0;

        char HopHost[256]={0}; ReverseResolve(HopIP,HopHost,sizeof(HopHost));
        int Reached=(strcmp(HopIP,DestIP)==0);
        const char *HC=Reached?CGreen:CWhite;

        char RttStr[64];
        if(Got==Queries) snprintf(RttStr,sizeof(RttStr),"%ldms / %ldms / %ldms",RttMin,RttAvg,RttMax);
        else             snprintf(RttStr,sizeof(RttStr),"%ldms (%d/%d)",RttAvg,Got,Queries);

        printf("  %s%s%-4d%s  %s%s%-20s%s  %s%s%-36s%s  %s%s%s%s\n",
            BD,CDim,Ttl,CR,
            BD,HC,HopIP,CR,
            CDim,CDim,(HopHost[0]&&strcmp(HopHost,HopIP)!=0)?HopHost:"",CR,
            LatCol(RttAvg),BD,RttStr,CR);

        if(Reached){printf("\n  %s%s[✓]%s Destination reached in %s%s%d%s hops\n",BD,CGreen,CR,BD,CWhite,Ttl,CR);break;}
    }
    printf("\n");
}

static void PrintDnsRecord(const char *Type, const char *Value, const char *Extra) {
    if(Extra&&Extra[0])
        printf("  %s%s%-7s%s  %s%s%-50s%s  %s%s%s%s\n",BD,CWhite,Type,CR,BD,CWhite,Value,CR,CDim,CDim,Extra,CR);
    else
        printf("  %s%s%-7s%s  %s%s%s%s\n",BD,CWhite,Type,CR,BD,CWhite,Value,CR);
}

static int DnsBuildQuery(unsigned char *Buf, int BufLen, const char *Host, uint16_t Qtype) {
    memset(Buf,0,BufLen);
    Buf[0]=0x12;Buf[1]=0x34;Buf[2]=0x01;Buf[3]=0x00;Buf[4]=0x00;Buf[5]=0x01;
    int Off=12; const char *P=Host;
    while(*P){
        const char *Dot=strchr(P,'.');int Len=Dot?(int)(Dot-P):(int)strlen(P);
        if(Off+Len+1>=BufLen)return -1;
        Buf[Off++]=(unsigned char)Len;memcpy(Buf+Off,P,Len);Off+=Len;
        if (!Dot) break;
        P = Dot + 1;
    }
    Buf[Off++]=0x00;Buf[Off++]=(Qtype>>8)&0xFF;Buf[Off++]=Qtype&0xFF;Buf[Off++]=0x00;Buf[Off++]=0x01;
    return Off;
}

static int DnsExpandName(const unsigned char *Pkt, int PktLen, int Off, char *Out, int OutLen) {
    int Jumped=0,JumpOff=-1,Steps=0; int Pos=Off; Out[0]='\0'; int OutOff=0;
    while(Pos<PktLen&&Steps++<128){
        unsigned char Len=Pkt[Pos];
        if((Len&0xC0)==0xC0){if(Pos+1>=PktLen)return -1;int NO=((Len&0x3F)<<8)|Pkt[Pos+1];if(!Jumped)JumpOff=Pos+2;Pos=NO;Jumped=1;continue;}
        if(Len==0){Pos++;break;}
        Pos++;if(OutOff>0&&OutOff<OutLen-1)Out[OutOff++]='.';
        int Copy=(Len<OutLen-OutOff-1)?Len:OutLen-OutOff-1;memcpy(Out+OutOff,Pkt+Pos,Copy);OutOff+=Copy;Pos+=Len;
    }
    Out[OutOff]='\0'; return Jumped?JumpOff:Pos;
}

static int DnsSendQuery(const char *Server, unsigned char *QBuf, int QLen, unsigned char *RBuf, int RBufLen) {
    int Sock=socket(AF_INET,SOCK_DGRAM,0); if(Sock<0)return -1;
    struct sockaddr_in SA;memset(&SA,0,sizeof(SA));SA.sin_family=AF_INET;SA.sin_port=htons(53);inet_pton(AF_INET,Server,&SA.sin_addr);
    struct timeval Tv={DnsTimeout,0};setsockopt(Sock,SOL_SOCKET,SO_RCVTIMEO,&Tv,sizeof(Tv));
    if(sendto(Sock,QBuf,QLen,0,(struct sockaddr*)&SA,sizeof(SA))<0){close(Sock);return -1;}
    int N=(int)recv(Sock,RBuf,RBufLen,0);close(Sock);return N;
}

static void DnsQuery(const char *Host, uint16_t Qtype, const char *TypeName, const char *Server) {
    unsigned char QBuf[512],RBuf[4096];
    int QLen=DnsBuildQuery(QBuf,sizeof(QBuf),Host,Qtype);if(QLen<0)return;
    int RLen=DnsSendQuery(Server,QBuf,QLen,RBuf,sizeof(RBuf));if(RLen<12)return;
    int Ancount=(RBuf[6]<<8)|RBuf[7];if(Ancount<=0)return;
    int Off=12;char Tmp[256];
    int Skip=DnsExpandName(RBuf,RLen,Off,Tmp,sizeof(Tmp));if(Skip<0)return;
    Off=Skip+4;
    for(int i=0;i<Ancount&&Off+10<RLen;i++){
        int NE=DnsExpandName(RBuf,RLen,Off,Tmp,sizeof(Tmp));if(NE<0)break;Off=NE;
        if(Off+10>RLen)break;
        uint16_t RType=(RBuf[Off]<<8)|RBuf[Off+1];
        uint32_t TTL=((uint32_t)RBuf[Off+4]<<24)|((uint32_t)RBuf[Off+5]<<16)|((uint32_t)RBuf[Off+6]<<8)|RBuf[Off+7];
        uint16_t RDLen=(RBuf[Off+8]<<8)|RBuf[Off+9];Off+=10;
        if(Off+RDLen>RLen)break;
        if(RType==Qtype){
            char Val[512]={0},Extra[128]={0};
            if(Qtype==1&&RDLen==4){snprintf(Val,sizeof(Val),"%d.%d.%d.%d",RBuf[Off],RBuf[Off+1],RBuf[Off+2],RBuf[Off+3]);}
            else if(Qtype==28&&RDLen==16){struct in6_addr A6;memcpy(&A6,RBuf+Off,16);inet_ntop(AF_INET6,&A6,Val,sizeof(Val));}
            else if(Qtype==15){uint16_t Prio=(RBuf[Off]<<8)|RBuf[Off+1];DnsExpandName(RBuf,RLen,Off+2,Val,sizeof(Val));snprintf(Extra,sizeof(Extra),"prio=%d ttl=%us",(int)Prio,(unsigned)TTL);}
            else if(Qtype==2||Qtype==5){DnsExpandName(RBuf,RLen,Off,Val,sizeof(Val));snprintf(Extra,sizeof(Extra),"ttl=%us",(unsigned)TTL);}
            else if(Qtype==16){int TLen=RBuf[Off];int TL=TLen<511?TLen:511;memcpy(Val,RBuf+Off+1,TL);Val[TL]='\0';}
            else if(Qtype==6){char MN[256]={0},RN[256]={0};int P2=DnsExpandName(RBuf,RLen,Off,MN,sizeof(MN));if(P2>0)DnsExpandName(RBuf,RLen,P2,RN,sizeof(RN));snprintf(Val,sizeof(Val),"%s",MN);snprintf(Extra,sizeof(Extra),"rname=%s ttl=%us",RN,(unsigned)TTL);}
            else if(Qtype==12){DnsExpandName(RBuf,RLen,Off,Val,sizeof(Val));}
            if(Val[0])PrintDnsRecord(TypeName,Val,Extra[0]?Extra:NULL);
        }
        Off+=RDLen;
    }
}

static void ModuleDns(int Argc, char **Argv) {
    char Host[256]={0},Server[64]="8.8.8.8";
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {printf("  %s%sdns%s module\n\n",BD,CDim,CR);printf("  %s%s-t%s %s<host>%s        Target domain\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-s%s %s<server>%s      DNS server IP (def: 8.8.8.8)\n\n",BD,CWhite,CR,CWhite,CR);return;}
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){strncpy(Host,  Argv[++i],sizeof(Host)-1);}
        else if(!strcmp(Argv[i],"-s")&&i+1<Argc){strncpy(Server,Argv[++i],sizeof(Server)-1);}
        else if(Argv[i][0]!='-'&&!Host[0])       {strncpy(Host,  Argv[i],  sizeof(Host)-1);}
    }
    if(!Host[0]){fprintf(stderr,"  %s%s[ERR]%s No target.\n\n",BD,CRed,CR);return;}

    char IP[64]={0};ResolveStr(Host,IP,sizeof(IP));

    printf("\n");printf("\n");
    printf("  %s%sDNS LOOKUP%s  %s%s%s%s",BD,CDim,CR,BD,CWhite,Host,CR);
    if(IP[0])printf("  %s%s(%s)%s",CDim,CDim,IP,CR);
    printf("  %s%s@%s%s\n",CDim,BD,Server,CR);
    printf("\n");printf("\n");
    printf("  %s%s%-7s  %-50s  %s%s\n\n",BD,CDim,"TYPE","VALUE","TTL/EXTRA",CR);

    DnsQuery(Host, 1,  "A",     Server);
    DnsQuery(Host, 28, "AAAA",  Server);
    DnsQuery(Host, 5,  "CNAME", Server);
    DnsQuery(Host, 15, "MX",    Server);
    DnsQuery(Host, 2,  "NS",    Server);
    DnsQuery(Host, 16, "TXT",   Server);
    DnsQuery(Host, 6,  "SOA",   Server);

    if(IP[0]){
        char RevBuf[128]={0};
        unsigned char O1,O2,O3,O4; sscanf(IP,"%hhu.%hhu.%hhu.%hhu",&O1,&O2,&O3,&O4);
        snprintf(RevBuf,sizeof(RevBuf),"%d.%d.%d.%d.in-addr.arpa",O4,O3,O2,O1);
        DnsQuery(RevBuf,12,"PTR",Server);
    }

    printf("\n");printf("\n");printf("\n");
}

static void ModuleWhois(int Argc, char **Argv) {
    char Target[256]={0};
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {printf("  %s%swhois%s module\n\n",BD,CWhite,CR);printf("  %s%s-t%s %s<ip|domain>%s  Target\n\n",BD,CWhite,CR,CWhite,CR);return;}
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){strncpy(Target,Argv[++i],sizeof(Target)-1);}
        else if(Argv[i][0]!='-'&&!Target[0])     {strncpy(Target,Argv[i], sizeof(Target)-1);}
    }
    if(!Target[0]){fprintf(stderr,"  %s%s[ERR]%s No target.\n\n",BD,CRed,CR);return;}

    char IP[64]={0};ResolveStr(Target,IP,sizeof(IP));if(!IP[0])snprintf(IP,sizeof(IP),"%s",Target);

    printf("\n");printf("\n");
    printf("  %s%sWHOIS%s  %s%s%s%s  %s%s(%s)%s\n",BD,CWhite,CR,BD,CWhite,Target,CR,CDim,CDim,IP,CR);
    printf("\n");printf("\n");

    const char *Servers[]={"whois.iana.org","whois.arin.net","whois.ripe.net","whois.apnic.net","whois.lacnic.net",NULL};
    int Found=0;
    for(int s=0;Servers[s]&&!Found;s++){
        long Lat=0;int Fd=TcpConnect(Servers[s],43,5,&Lat);if(Fd<0)continue;
        char Query[512];snprintf(Query,sizeof(Query),"%s\r\n",IP);
        SendAll(Fd,(unsigned char*)Query,(int)strlen(Query));
        char Buf[16384];memset(Buf,0,sizeof(Buf));int Total=0;
        fd_set R;struct timeval Tv={5,0};
        while(Total<(int)sizeof(Buf)-1){FD_ZERO(&R);FD_SET(Fd,&R);Tv.tv_sec=5;Tv.tv_usec=0;if(select(Fd+1,&R,NULL,NULL,&Tv)<=0)break;int N=(int)recv(Fd,Buf+Total,sizeof(Buf)-Total-1,0);if(N<=0)break;Total+=N;}
        close(Fd);
        if(Total<20)continue;
        Found=1;
        printf("  %s%ssource%s  %s%s%s%s  %s%s(%ldms)%s\n\n",BD,CDim,CR,BD,CWhite,Servers[s],CR,CDim,CDim,Lat,CR);

        char *ReferServer[64];int RefCount=0;
        char BufCopy[16384];snprintf(BufCopy,sizeof(BufCopy),"%s",Buf);
        char *Line=strtok(BufCopy,"\n");
        while(Line){
            TrimLine(Line);
            if(!Line[0]||Line[0]=='%'||Line[0]=='#'||Line[0]==';'){Line=strtok(NULL,"\n");continue;}
            char *Colon=strchr(Line,':');
            if(Colon){
                *Colon='\0';char *Val=Colon+1;while(*Val==' ')Val++;
                TrimLine((char*)Line);TrimLine(Val);
                if(!Val[0]){Line=strtok(NULL,"\n");continue;}
                if(strcasecmp(Line,"refer")==0||strcasecmp(Line,"whois")==0)
                    if(RefCount<64)ReferServer[RefCount++]=(char*)Val;
                const char *KC=CWhite;
                if(strcasestr(Line,"netname")||strcasestr(Line,"orgname")||strcasestr(Line,"org-name"))KC=CWhite;
                else if(strcasestr(Line,"country"))KC=CGreen;
                else if(strcasestr(Line,"inetnum")||strcasestr(Line,"netrange"))KC=CBlue;
                else if(strcasestr(Line,"descr")||strcasestr(Line,"remarks"))KC=CDim;
                else if(strcasestr(Line,"abuse")||strcasestr(Line,"route"))KC=CDim;
                printf("  %s%s%-22s%s  %s%s%s%s\n",BD,CWhite,Line,CR,BD,KC,Val,CR);
            }
            Line=strtok(NULL,"\n");
        }
        (void)ReferServer;(void)RefCount;
    }
    printf("\n");printf("\n");printf("\n");
}

static void ModuleHTTP(int Argc, char **Argv) {
    char Url[512]={0},Method[16]="GET"; int ShowBody=0,Timeout=10,MaxRedir=5;
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {printf("  %s%shttp%s module\n\n",BD,CBlue,CR);printf("  %s%s-u%s %s<url>%s       URL\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-m%s %s<method>%s   Method (def: GET)\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-b%s            Show body\n",BD,CWhite,CR);printf("  %s%s-r%s %s<n>%s         Follow redirects (def: 5)\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-w%s %s<sec>%s       Timeout (def: 10)\n\n",BD,CWhite,CR,CWhite,CR);return;}
        else if(!strcmp(Argv[i],"-u")&&i+1<Argc){strncpy(Url,   Argv[++i],sizeof(Url)-1);}
        else if(!strcmp(Argv[i],"-m")&&i+1<Argc){strncpy(Method,Argv[++i],sizeof(Method)-1);}
        else if(!strcmp(Argv[i],"-w")&&i+1<Argc){Timeout=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-r")&&i+1<Argc){MaxRedir=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-b"))           {ShowBody=1;}
        else if(Argv[i][0]!='-'&&!Url[0])        {strncpy(Url,Argv[i],sizeof(Url)-1);}
    }
    if(!Url[0]){fprintf(stderr,"  %s%s[ERR]%s No URL.\n\n",BD,CRed,CR);return;}

    char CurUrl[512]; snprintf(CurUrl,sizeof(CurUrl),"%s",Url);
    int RedirCount=0;

    while(1){
        char Proto[8]="http",Host[256]={0},Path[512]="/"; int Port=80;
        char *Sl=strstr(CurUrl,"://");
        if(Sl){size_t PL=(size_t)(Sl-CurUrl);if(PL<sizeof(Proto)){memcpy(Proto,CurUrl,PL);Proto[PL]='\0';}Sl+=3;}else Sl=CurUrl;
        if(strcasecmp(Proto,"https")==0)Port=443;
        char *PS=strchr(Sl,'/');
        if(PS){strncpy(Path,PS,sizeof(Path)-1);size_t HL=(size_t)(PS-Sl);if(HL>=sizeof(Host))HL=sizeof(Host)-1;memcpy(Host,Sl,HL);Host[HL]='\0';}
        else { snprintf(Host, sizeof(Host), "%.*s", (int)(sizeof(Host)-1), Sl); }
        char *CP=strchr(Host,':');if(CP){Port=atoi(CP+1);*CP='\0';}

        char IP[64]={0};ResolveStr(Host,IP,sizeof(IP));

        printf("\n");printf("\n");
        printf("  %s%s%s%s  %s%s%s%s  %s%s%s:%d%s%s%s\n",BD,CWhite,Method,CR,BD,CWhite,Host,CR,CDim,CDim,Host,Port,Path,CR,"");
        printf("  %s%sproto%s %s%s%s%s  %s%sip%s %s%s%s%s",BD,CDim,CR,BD,CWhite,Proto,CR,BD,CDim,CR,BD,CBlue,IP,CR);
        if(RedirCount>0)printf("  %s%sredirect%s %s%s%d%s",BD,CDim,CR,BD,CDim,RedirCount,CR);
        printf("\n");printf("\n");printf("\n");

        long Lat=0;int Fd=TcpConnect(Host,Port,Timeout,&Lat);
        if(Fd<0){fprintf(stderr,"  %s%s[ERR]%s Cannot connect to %s:%d\n\n",BD,CRed,CR,Host,Port);return;}

        char Req[4096];
        snprintf(Req,sizeof(Req),"%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: HTONSpider/%s\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",Method,Path,Host,VersionStr);
        SendAll(Fd,(unsigned char*)Req,(int)strlen(Req));

        char Resp[65536];memset(Resp,0,sizeof(Resp));int Total=0;
        fd_set R;struct timeval Tv;
        while(Total<(int)sizeof(Resp)-1){FD_ZERO(&R);FD_SET(Fd,&R);Tv.tv_sec=Timeout;Tv.tv_usec=0;if(select(Fd+1,&R,NULL,NULL,&Tv)<=0)break;int N=(int)recv(Fd,Resp+Total,sizeof(Resp)-Total-1,0);if(N<=0)break;Total+=N;}
        close(Fd);

        char *HEnd=strstr(Resp,"\r\n\r\n");if(!HEnd)HEnd=strstr(Resp,"\n\n");
        char *Body=HEnd?(HEnd+(strncmp(HEnd,"\r\n",2)==0?4:2)):NULL;
        char Hdrs[32768];memset(Hdrs,0,sizeof(Hdrs));
        if(HEnd){size_t HL=(size_t)(HEnd-Resp);if(HL>=sizeof(Hdrs))HL=sizeof(Hdrs)-1;memcpy(Hdrs,Resp,HL);}
        else snprintf(Hdrs,sizeof(Hdrs),"%s",Resp);

        int StatusCode=0; char StatusLine[256]={0};
        char *CRLF=strchr(Hdrs,'\n');
        if(CRLF){size_t SL=(size_t)(CRLF-Hdrs);if(SL>=sizeof(StatusLine))SL=sizeof(StatusLine)-1;memcpy(StatusLine,Hdrs,SL);TrimLine(StatusLine);}
        sscanf(StatusLine,"HTTP/%*s %d",&StatusCode);

        const char *SC=CGreen;
        if(StatusCode>=500)SC=CRed;else if(StatusCode>=400)SC=CDim;else if(StatusCode>=300)SC=CWhite;else if(StatusCode>=200)SC=CGreen;

        printf("  %s%s%s%s  %s%sconnect:%ldms%s  %s%sbytes:%d%s\n\n",BD,SC,StatusLine,CR,CDim,CDim,Lat,CR,CDim,CDim,Total,CR);

        char *Location=NULL;
        char *Line=strtok(Hdrs,"\n");int First=1;
        while(Line){
            TrimLine(Line);if(!Line[0]){Line=strtok(NULL,"\n");continue;}
            if(First){First=0;Line=strtok(NULL,"\n");continue;}
            char *Col=strchr(Line,':');
            if(Col){
                *Col='\0';char *Val=Col+1;while(*Val==' ')Val++;TrimLine(Line);TrimLine(Val);
                const char *VC=CWhite;
                if(strcasecmp(Line,"server")==0||strcasecmp(Line,"x-powered-by")==0)VC=CWhite;
                else if(strcasecmp(Line,"content-type")==0)VC=CWhite;
                else if(strcasecmp(Line,"content-length")==0)VC=CBlue;
                else if(strcasecmp(Line,"location")==0){VC=CDim;Location=Val;}
                else if(strcasestr(Line,"security")||strcasestr(Line,"strict-transport"))VC=CGreen;
                else if(strcasestr(Line,"cookie")||strcasestr(Line,"set-cookie"))VC=CBlue;
                else if(strcasestr(Line,"cache"))VC=CBlue;
                printf("  %s%s%-32s%s  %s%s%s%s\n",BD,CWhite,Line,CR,BD,VC,Val,CR);
            }
            Line=strtok(NULL,"\n");
        }

        if(ShowBody&&Body&&*Body){
            int BLen=(int)strlen(Body);if(BLen>4096)BLen=4096;
            printf("\n  %s%sBODY%s  %s%s(%d bytes shown)%s\n",BD,CDim,CR,CDim,CDim,BLen,CR);
            printf("\n");
            printf("%s%s%.*s%s\n",CDim,CDim,BLen,Body,CR);
            if((int)strlen(Body)>4096)printf("  %s%s... truncated%s\n",CDim,CDim,CR);
        }

        printf("\n");printf("\n");printf("\n");

        if((StatusCode==301||StatusCode==302||StatusCode==303||StatusCode==307||StatusCode==308)&&Location&&RedirCount<MaxRedir){
            printf("  %s%s[→]%s Redirect to %s%s%s%s\n\n",BD,CDim,CR,BD,CDim,Location,CR);
            if(strncmp(Location,"http",4)==0)strncpy(CurUrl,Location,sizeof(CurUrl)-1);
            else{snprintf(CurUrl,sizeof(CurUrl),"%s://%s%s",Proto,Host,Location);}
            RedirCount++;continue;
        }
        break;
    }
}

static void ModuleIfinfo(int Argc, char **Argv) {
    (void)Argc;(void)Argv;
    printf("\n");printf("\n");
    printf("  %s%sNETWORK INTERFACES%s\n",BD,CBlue,CR);
    printf("\n");printf("\n");

    struct ifaddrs *IfList,*Ifa;
    if(getifaddrs(&IfList)<0){fprintf(stderr,"  %s%s[ERR]%s getifaddrs failed\n\n",BD,CRed,CR);return;}

    char Seen[64][32];int SeenCount=0;
    for(Ifa=IfList;Ifa;Ifa=Ifa->ifa_next){
        if(!Ifa->ifa_addr)continue;
        int Already=0;
        for(int s=0;s<SeenCount;s++)if(!strcmp(Seen[s],Ifa->ifa_name)){Already=1;break;}
        if(Already)continue;
        if(SeenCount<64)strncpy(Seen[SeenCount++],Ifa->ifa_name,31);

        unsigned int Flags=Ifa->ifa_flags;
        char FlagStr[128]={0};
        if(Flags&IFF_UP)     strcat(FlagStr,"UP ");
        if(Flags&IFF_RUNNING)strcat(FlagStr,"RUNNING ");
        if(Flags&IFF_LOOPBACK)strcat(FlagStr,"LOOPBACK ");
        if(Flags&IFF_BROADCAST)strcat(FlagStr,"BROADCAST ");
        if(Flags&IFF_MULTICAST)strcat(FlagStr,"MULTICAST ");
        if(Flags&IFF_POINTOPOINT)strcat(FlagStr,"P2P ");
        TrimLine(FlagStr);

        printf("  %s%s%s%s  %s%s%s%s\n",BD,CBlue,Ifa->ifa_name,CR,CDim,CDim,FlagStr,CR);

        int Sock=socket(AF_INET,SOCK_DGRAM,0);
        if(Sock>=0){
            struct ifreq Ifr;memset(&Ifr,0,sizeof(Ifr));strncpy(Ifr.ifr_name,Ifa->ifa_name,IFNAMSIZ-1);
            if(ioctl(Sock,SIOCGIFMTU,&Ifr)==0)
                printf("    %s%smtu%s      %s%s%d%s\n",BD,CDim,CR,BD,CWhite,Ifr.ifr_mtu,CR);
#ifdef SIOCGIFHWADDR
            struct ifreq IfHw;memset(&IfHw,0,sizeof(IfHw));strncpy(IfHw.ifr_name,Ifa->ifa_name,IFNAMSIZ-1);
            if(ioctl(Sock,SIOCGIFHWADDR,&IfHw)==0){
                unsigned char *Mac=(unsigned char*)IfHw.ifr_hwaddr.sa_data;
                printf("    %s%smac%s      %s%s%02x:%02x:%02x:%02x:%02x:%02x%s\n",BD,CDim,CR,BD,CWhite,Mac[0],Mac[1],Mac[2],Mac[3],Mac[4],Mac[5],CR);
            }
#endif
            close(Sock);
        }

        for(struct ifaddrs *I2=IfList;I2;I2=I2->ifa_next){
            if(strcmp(I2->ifa_name,Ifa->ifa_name)!=0||!I2->ifa_addr)continue;
            int Fam=I2->ifa_addr->sa_family;
            if(Fam==AF_INET){
                char AddrS[64]={0},MaskS[64]={0},BcastS[64]={0};
                inet_ntop(AF_INET,&((struct sockaddr_in*)I2->ifa_addr)->sin_addr,AddrS,sizeof(AddrS));
                if(I2->ifa_netmask)inet_ntop(AF_INET,&((struct sockaddr_in*)I2->ifa_netmask)->sin_addr,MaskS,sizeof(MaskS));
                if(I2->ifa_broadaddr)inet_ntop(AF_INET,&((struct sockaddr_in*)I2->ifa_broadaddr)->sin_addr,BcastS,sizeof(BcastS));
                printf("    %s%sinet%s     %s%s%s%s  %s%smask %s%s  %s%sbcast %s%s\n",BD,CDim,CR,BD,CGreen,AddrS,CR,CDim,CDim,MaskS,CR,CDim,CDim,BcastS,CR);
            } else if(Fam==AF_INET6){
                char AddrS[64]={0};
                inet_ntop(AF_INET6,&((struct sockaddr_in6*)I2->ifa_addr)->sin6_addr,AddrS,sizeof(AddrS));
                printf("    %s%sinet6%s    %s%s%s%s\n",BD,CDim,CR,BD,CBlue,AddrS,CR);
            }
        }

        char TxFile[256],RxFile[256],TxErrFile[256],RxErrFile[256];
        snprintf(TxFile, sizeof(TxFile), "/sys/class/net/%s/statistics/tx_bytes",  Ifa->ifa_name);
        snprintf(RxFile, sizeof(RxFile), "/sys/class/net/%s/statistics/rx_bytes",  Ifa->ifa_name);
        snprintf(TxErrFile,sizeof(TxErrFile),"/sys/class/net/%s/statistics/tx_errors",Ifa->ifa_name);
        snprintf(RxErrFile,sizeof(RxErrFile),"/sys/class/net/%s/statistics/rx_errors",Ifa->ifa_name);
        FILE *Fp; char FBuf[32];
        unsigned long long TxB=0,RxB=0,TxE=0,RxE=0;
        if ((Fp=fopen(TxFile,   "r"))!=NULL){if(fgets(FBuf,sizeof(FBuf),Fp))TxB=strtoull(FBuf,NULL,10);fclose(Fp);}
        if ((Fp=fopen(RxFile,   "r"))!=NULL){if(fgets(FBuf,sizeof(FBuf),Fp))RxB=strtoull(FBuf,NULL,10);fclose(Fp);}
        if ((Fp=fopen(TxErrFile,"r"))!=NULL){if(fgets(FBuf,sizeof(FBuf),Fp))TxE=strtoull(FBuf,NULL,10);fclose(Fp);}
        if ((Fp=fopen(RxErrFile,"r"))!=NULL){if(fgets(FBuf,sizeof(FBuf),Fp))RxE=strtoull(FBuf,NULL,10);fclose(Fp);}
        if(TxB||RxB){
            char TxS[32],RxS[32];
            if(TxB>1073741824)snprintf(TxS,sizeof(TxS),"%.2f GB",(double)TxB/1073741824.0);
            else if(TxB>1048576)snprintf(TxS,sizeof(TxS),"%.2f MB",(double)TxB/1048576.0);
            else if(TxB>1024)snprintf(TxS,sizeof(TxS),"%.2f KB",(double)TxB/1024.0);
            else snprintf(TxS,sizeof(TxS),"%llu B",TxB);
            if(RxB>1073741824)snprintf(RxS,sizeof(RxS),"%.2f GB",(double)RxB/1073741824.0);
            else if(RxB>1048576)snprintf(RxS,sizeof(RxS),"%.2f MB",(double)RxB/1048576.0);
            else if(RxB>1024)snprintf(RxS,sizeof(RxS),"%.2f KB",(double)RxB/1024.0);
            else snprintf(RxS,sizeof(RxS),"%llu B",RxB);
            printf("    %s%stx%s       %s%s%s%s  %s%serr:%llu%s\n",BD,CDim,CR,BD,CDim,TxS,CR,CDim,CDim,TxE,CR);
            printf("    %s%srx%s       %s%s%s%s  %s%serr:%llu%s\n",BD,CDim,CR,BD,CGreen, RxS,CR,CDim,CDim,RxE,CR);
        }
        printf("\n");
    }
    freeifaddrs(IfList);
    printf("\n");printf("\n");
}

static void ModuleBanner(int Argc, char **Argv) {
    char Host[256]={0},SendData[512]={0}; int Port=80,Timeout=5,UdpMode=0,HexDump=0;
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {printf("  %s%sbanner%s module\n\n",BD,CGreen,CR);printf("  %s%s-t%s %s<host>%s    Target\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-p%s %s<port>%s    Port (def: 80)\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-d%s %s<data>%s    Custom payload\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-w%s %s<sec>%s     Timeout\n",BD,CWhite,CR,CWhite,CR);printf("  %s%s-u%s           UDP mode\n",BD,CWhite,CR);printf("  %s%s-x%s           Hex dump\n\n",BD,CWhite,CR);return;}
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){strncpy(Host,    Argv[++i],sizeof(Host)-1);}
        else if(!strcmp(Argv[i],"-p")&&i+1<Argc){Port   =atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-w")&&i+1<Argc){Timeout=atoi(Argv[++i]);}
        else if(!strcmp(Argv[i],"-d")&&i+1<Argc){strncpy(SendData,Argv[++i],sizeof(SendData)-1);}
        else if(!strcmp(Argv[i],"-u"))           {UdpMode=1;}
        else if(!strcmp(Argv[i],"-x"))           {HexDump=1;}
        else if(Argv[i][0]!='-'&&!Host[0])       {strncpy(Host,Argv[i],sizeof(Host)-1);}
    }
    if(!Host[0]){fprintf(stderr,"  %s%s[ERR]%s No target.\n\n",BD,CRed,CR);return;}
    char IP[64]={0};ResolveStr(Host,IP,sizeof(IP));if(!IP[0])snprintf(IP,sizeof(IP),"%s",Host);

    printf("\n");printf("\n");
    printf("  %s%sBANNER GRAB%s  %s%s%s:%d%s  %s%s(%s)%s  %s%s%s%s\n",
        BD,CGreen,CR,BD,CWhite,Host,Port,CR,CDim,CDim,IP,CR,BD,CWhite,UdpMode?"UDP":"TCP",CR);
    printf("\n");printf("\n");

    unsigned char Buf[8192];memset(Buf,0,sizeof(Buf));int Total=0;long Lat=0;

    if(UdpMode){
        int Sock=socket(AF_INET,SOCK_DGRAM,0);
        if(Sock<0){fprintf(stderr,"  %s%s[ERR]%s Socket failed.\n\n",BD,CRed,CR);return;}
        struct sockaddr_in Addr;memset(&Addr,0,sizeof(Addr));Addr.sin_family=AF_INET;Addr.sin_port=htons((uint16_t)Port);inet_pton(AF_INET,IP,&Addr.sin_addr);
        const char *Pl=SendData[0]?SendData:"\r\n";
        sendto(Sock,Pl,strlen(Pl),0,(struct sockaddr*)&Addr,sizeof(Addr));
        struct timeval Tv={Timeout,0};setsockopt(Sock,SOL_SOCKET,SO_RCVTIMEO,&Tv,sizeof(Tv));
        Total=(int)recv(Sock,Buf,sizeof(Buf)-1,0);close(Sock);
    } else {
        int Fd=TcpConnect(Host,Port,Timeout,&Lat);
        if(Fd<0){fprintf(stderr,"  %s%s[ERR]%s Cannot connect.\n\n",BD,CRed,CR);return;}
        const char *Pl=SendData[0]?SendData:NULL;
        if(Pl){SendAll(Fd,(unsigned char*)Pl,(int)strlen(Pl));}
        else{char Rq[256];snprintf(Rq,sizeof(Rq),"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n",Host);SendAll(Fd,(unsigned char*)Rq,(int)strlen(Rq));}
        fd_set R;struct timeval Tv;
        while(Total<(int)sizeof(Buf)-1){FD_ZERO(&R);FD_SET(Fd,&R);Tv.tv_sec=Timeout;Tv.tv_usec=0;if(select(Fd+1,&R,NULL,NULL,&Tv)<=0)break;int N=(int)recv(Fd,Buf+Total,sizeof(Buf)-Total-1,0);if(N<=0)break;Total+=N;}
        close(Fd);
    }

    if(Total<=0){printf("  %s%s[--]%s No response received.\n\n",BD,CRed,CR);return;}
    printf("  %s%sconnect:%ldms%s  %s%sbytes:%d%s\n\n",CDim,CDim,Lat,CR,CDim,CDim,Total,CR);

    if(HexDump){
        printf("  %s%sHEX DUMP%s\n\n",BD,CWhite,CR);
        for(int i=0;i<Total;i+=16){
            printf("  %s%s%08x%s  ",BD,CDim,i,CR);
            for(int j=0;j<16;j++){
                if(i+j<Total)printf("%s%s%02x%s ",BD,CWhite,Buf[i+j],CR);
                else printf("   ");
                if(j==7)printf(" ");
            }
            printf("  %s%s",BD,CWhite);
            for(int j=0;j<16&&i+j<Total;j++)printf("%c",isprint(Buf[i+j])?Buf[i+j]:'.');
            printf("%s\n",CR);
        }
    } else {
        for(int i=0;i<Total;i++)if(!isprint(Buf[i])&&Buf[i]!='\n'&&Buf[i]!='\r'&&Buf[i]!='\t')Buf[i]='.';
        printf("%s%s%s%s\n",BD,CDim,(char*)Buf,CR);
    }
    printf("\n");printf("\n");printf("\n");
}

static void ModuleSubnet(int Argc, char **Argv) {
    char Input[128]={0};
    for(int i=0;i<Argc;i++){
        if     (!strcmp(Argv[i],"-h"))           {printf("  %s%ssubnet%s module\n\n",BD,CWhite,CR);printf("  %s%s-t%s %s<ip/cidr>%s  e.g. 192.168.1.0/24\n\n",BD,CWhite,CR,CWhite,CR);return;}
        else if(!strcmp(Argv[i],"-t")&&i+1<Argc){strncpy(Input,Argv[++i],sizeof(Input)-1);}
        else if(Argv[i][0]!='-'&&!Input[0])      {strncpy(Input,Argv[i], sizeof(Input)-1);}
    }
    if(!Input[0]){fprintf(stderr,"  %s%s[ERR]%s No input.\n\n",BD,CRed,CR);return;}

    char IPPart[64]={0};int Cidr=32;
    char *Sl=strchr(Input,'/');
    if(Sl){*Sl='\0';snprintf(IPPart,sizeof(IPPart),"%s",Input);Cidr=atoi(Sl+1);}
    else snprintf(IPPart,sizeof(IPPart),"%s",Input);

    struct in_addr Addr;
    if(inet_pton(AF_INET,IPPart,&Addr)!=1){fprintf(stderr,"  %s%s[ERR]%s Invalid IP: %s\n\n",BD,CRed,CR,IPPart);return;}
    if(Cidr<0||Cidr>32){fprintf(stderr,"  %s%s[ERR]%s CIDR must be 0-32\n\n",BD,CRed,CR);return;}

    uint32_t IP32=ntohl(Addr.s_addr);
    uint32_t Mask32=Cidr>0?(0xFFFFFFFF<<(32-Cidr)):0;
    uint32_t Net32=IP32&Mask32,Bcast=Net32|(~Mask32);
    uint32_t First=Net32+1,Last=Bcast-1;
    uint64_t Hosts=Cidr<=30?(uint64_t)(1U<<(32-Cidr))-2:(Cidr==31?2:1);
    uint32_t Wild=~Mask32;

    char NetS[32],MaskS[32],BcastS[32],FirstS[32],LastS[32],WildS[32];
    struct in_addr T;
    T.s_addr=htonl(Net32);  inet_ntop(AF_INET,&T,NetS,  sizeof(NetS));
    T.s_addr=htonl(Mask32); inet_ntop(AF_INET,&T,MaskS, sizeof(MaskS));
    T.s_addr=htonl(Bcast);  inet_ntop(AF_INET,&T,BcastS,sizeof(BcastS));
    T.s_addr=htonl(First);  inet_ntop(AF_INET,&T,FirstS,sizeof(FirstS));
    T.s_addr=htonl(Last);   inet_ntop(AF_INET,&T,LastS, sizeof(LastS));
    T.s_addr=htonl(Wild);   inet_ntop(AF_INET,&T,WildS, sizeof(WildS));

    const char *Class="Unknown";
    uint8_t O1=(IP32>>24)&0xFF;
    if(O1<=127)Class="A";else if(O1<=191)Class="B";else if(O1<=223)Class="C";else if(O1<=239)Class="D (Multicast)";else Class="E (Reserved)";
    int IsPrivate=((O1==10)||(O1==172&&((IP32>>16&0xFF)>=16&&(IP32>>16&0xFF)<=31))||(O1==192&&((IP32>>8&0xFF)==168)));

    printf("\n");printf("\n");
    printf("  %s%sSUBNET CALCULATOR%s  %s%s%s/%d%s\n",BD,CWhite,CR,BD,CWhite,IPPart,Cidr,CR);
    printf("\n");printf("\n");
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD,CWhite,"Network",     CR,BD,CWhite,NetS,  CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD,CWhite,"Subnet Mask", CR,BD,CWhite,MaskS, CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD,CWhite,"Wildcard Mask",CR,BD,CDim,WildS, CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD,CWhite,"Broadcast",   CR,BD,CWhite,BcastS,CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD,CWhite,"First Host",  CR,BD,CGreen, FirstS,CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD,CWhite,"Last Host",   CR,BD,CGreen, LastS, CR);
    printf("  %s%s%-18s%s  %s%s%llu%s\n",BD,CWhite,"Usable Hosts",CR,BD,CBlue,(unsigned long long)Hosts,CR);
    printf("  %s%s%-18s%s  %s%s/%d%s\n", BD,CWhite,"CIDR",        CR,BD,CDim,Cidr,  CR);
    printf("  %s%s%-18s%s  %s%sClass %s%s\n",BD,CWhite,"IP Class",CR,BD,CBlue, Class, CR);
    printf("  %s%s%-18s%s  %s%s%s%s\n",  BD,CWhite,"Scope",       CR,BD,IsPrivate?CWhite:CGreen,IsPrivate?"Private (RFC1918)":"Public",CR);
    printf("\n");printf("\n");printf("\n");
}

static void ModuleIP(int Argc, char **Argv) {
    (void)Argc;(void)Argv;
    printf("\n");printf("\n");
    printf("  %s%sPUBLIC IP INFO%s\n",BD,CBlue,CR);
    printf("\n");printf("\n");

    const char *Providers[]={"ip-api.com","ifconfig.me","api.ipify.org",NULL};
    for(int p=0;Providers[p];p++){
        long Lat=0;int Fd=TcpConnect(Providers[p],80,5,&Lat);if(Fd<0)continue;
        char Req[512];
        if(strcmp(Providers[p],"ip-api.com")==0)
            snprintf(Req,sizeof(Req),"GET /json HTTP/1.1\r\nHost: ip-api.com\r\nUser-Agent: HTONSpider/%s\r\nConnection: close\r\n\r\n",VersionStr);
        else
            snprintf(Req,sizeof(Req),"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: HTONSpider/%s\r\nConnection: close\r\n\r\n",Providers[p],VersionStr);
        SendAll(Fd,(unsigned char*)Req,(int)strlen(Req));
        char Resp[4096];memset(Resp,0,sizeof(Resp));int Total=0;
        fd_set R;struct timeval Tv={5,0};
        while(Total<(int)sizeof(Resp)-1){FD_ZERO(&R);FD_SET(Fd,&R);Tv.tv_sec=5;Tv.tv_usec=0;if(select(Fd+1,&R,NULL,NULL,&Tv)<=0)break;int N=(int)recv(Fd,Resp+Total,sizeof(Resp)-Total-1,0);if(N<=0)break;Total+=N;}
        close(Fd);
        char *Body=strstr(Resp,"\r\n\r\n");if(Body)Body+=4;else Body=Resp;

        printf("  %s%ssource%s  %s%s%s%s  %s%s(%ldms)%s\n\n",BD,CDim,CR,BD,CWhite,Providers[p],CR,CDim,CDim,Lat,CR);

        if(strcmp(Providers[p],"ip-api.com")==0&&Body){
            const char *Keys[]={"query","country","countryCode","regionName","city","zip","isp","org","as","timezone","lat","lon",NULL};
            const char *Labels[]={"IP Address","Country","Country Code","Region","City","ZIP","ISP","Organization","ASN","Timezone","Latitude","Longitude",NULL};
            for(int k=0;Keys[k];k++){
                char SearchKey[64];snprintf(SearchKey,sizeof(SearchKey),"\"%s\":",Keys[k]);
                char *Found=strstr(Body,SearchKey);
                if(!Found)continue;
                char *ValStart=Found+strlen(SearchKey);while(*ValStart==' ')ValStart++;
                char Val[256]={0};
                if(*ValStart=='"'){ValStart++;char *End=strchr(ValStart,'"');if(End){int L=(int)(End-ValStart);if(L>=256)L=255;memcpy(Val,ValStart,L);Val[L]='\0';}}
                else{char *End=ValStart;while(*End&&*End!=','&&*End!='}')End++;int L=(int)(End-ValStart);if(L>=256)L=255;memcpy(Val,ValStart,L);Val[L]='\0';TrimLine(Val);}
                const char *VC=CWhite;
                if(k==0)VC=CBlue;else if(k==1||k==2)VC=CGreen;else if(k==7||k==8)VC=CWhite;else if(k==9)VC=CDim;
                printf("  %s%s%-14s%s  %s%s%s%s\n",BD,CWhite,Labels[k],CR,BD,VC,Val,CR);
            }
        } else if(Body){
            TrimLine(Body);printf("  %s%s%s%s\n",BD,CBlue,Body,CR);
        }
        printf("\n");printf("\n");printf("\n");
        break;
    }
}

static const char *SubWordlist[] = {
    "www","mail","ftp","smtp","pop","imap","ns1","ns2","ns3","ns4","mx","mx1","mx2",
    "api","dev","staging","test","demo","beta","alpha","cdn","static","assets","img",
    "images","media","upload","download","files","docs","doc","wiki","kb","help","support",
    "admin","panel","cp","cpanel","webmail","blog","forum","shop","store","app","apps",
    "m","mobile","wap","portal","secure","ssl","vpn","remote","rdp","ssh","sftp","git",
    "gitlab","github","jenkins","jira","confluence","sonar","monitor","nagios","zabbix",
    "grafana","prometheus","kibana","elastic","solr","redis","mysql","db","database","sql",
    "mongo","postgres","oracle","mssql","phpmyadmin","pma","adminer","backup","bak",
    "old","new","v1","v2","v3","prod","production","uat","qa","stage","pre","preview",
    "internal","intranet","extranet","corp","corporate","office","hr","finance","legal",
    "marketing","sales","ops","devops","infra","cloud","aws","azure","gcp","k8s","docker",
    "registry","repo","maven","npm","pypi","proxy","gateway","lb","loadbalancer","ha",
    "cluster","node","worker","master","slave","primary","secondary","replica","dr",
    "vpn2","fw","firewall","router","switch","wifi","wlan","ap","mx3","ns5","dns",
    "dns1","dns2","autodiscover","autoconfig","_dmarc","dkim","spf","pop3","smtp2",
    "relay","exchange","owa","outlook","calendar","video","stream","live","webrtc",
    "turn","stun","chat","im","slack","meet","zoom","teams","crm","erp","cms","wp",
    "wordpress","drupal","joomla","magento","woocommerce","prestashop","opencart",
    "reporting","report","analytics","bi","dashboard","status","health","ping","uptime",
    "log","logs","syslog","audit","scan","vuln","pentest","sec","security","cert",
    "ca","pki","crl","ocsp","ldap","ad","sso","auth","oauth","saml","idp","sp",NULL
};

typedef struct {
    char  Domain[256];
    char  Sub[64];
    char  Full[320];
    char  IP[64];
    int   Alive;
    int   HttpStatus;
    int   HttpsStatus;
    long  HttpLatency;
    char  Title[128];
    char  Redirect[256];
    int   PortOpen[8];
    int   PortList[8];
    int   PortCount;
} SubResult;

typedef struct {
    const char      *Domain;
    const char      *Prefix;
    char             DnsServer[64];
    SubResult       *Results;
    int              Index;
    int              DnsTimeout2;
    int              HttpProbe;
    int              CheckPorts[8];
    int              CheckPortCount;
    pthread_mutex_t *Lock;
    volatile int    *Count;
    volatile int    *Found;
} SubWorkerArg;

static int DnsResolveA(const char *Host, char *OutIP, const char *Server, int TimeoutSec) {
    unsigned char QBuf[512], RBuf[512];
    int QLen = DnsBuildQuery(QBuf, sizeof(QBuf), Host, 1);
    if (QLen < 0) return -1;

    int Sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (Sock < 0) return -1;
    struct sockaddr_in SA; memset(&SA, 0, sizeof(SA));
    SA.sin_family = AF_INET;
    SA.sin_port   = htons(53);
    inet_pton(AF_INET, Server, &SA.sin_addr);
    struct timeval Tv = { TimeoutSec, 0 };
    setsockopt(Sock, SOL_SOCKET, SO_RCVTIMEO, &Tv, sizeof(Tv));
    setsockopt(Sock, SOL_SOCKET, SO_SNDTIMEO, &Tv, sizeof(Tv));
    if (sendto(Sock, QBuf, QLen, 0, (struct sockaddr*)&SA, sizeof(SA)) < 0) {
        close(Sock); return -1;
    }
    int RLen = (int)recv(Sock, RBuf, sizeof(RBuf), 0);
    close(Sock);
    if (RLen < 12) return -1;

    int Rcode = RBuf[3] & 0x0F;
    if (Rcode != 0) return -1;

    int Ancount = (RBuf[6] << 8) | RBuf[7];
    if (Ancount <= 0) return -1;
    int Off = 12;
    char Tmp[256];
    int Skip = DnsExpandName(RBuf, RLen, Off, Tmp, sizeof(Tmp));
    if (Skip < 0) return -1;
    Off = Skip + 4;
    for (int i = 0; i < Ancount && Off + 10 < RLen; i++) {
        int NE = DnsExpandName(RBuf, RLen, Off, Tmp, sizeof(Tmp));
        if (NE < 0) break;
        Off = NE;
        if (Off + 10 > RLen) break;
        uint16_t RType = (RBuf[Off] << 8) | RBuf[Off+1];
        uint16_t RDLen = (RBuf[Off+8] << 8) | RBuf[Off+9];
        Off += 10;
        if (Off + RDLen > RLen) break;
        if (RType == 1 && RDLen == 4) {
            snprintf(OutIP, 64, "%d.%d.%d.%d",
                RBuf[Off], RBuf[Off+1], RBuf[Off+2], RBuf[Off+3]);
            return 0;
        }
        Off += RDLen;
    }
    return -1;
}

static const char *StatusColor(int Code) {
    if (Code >= 200 && Code < 300) return "\033[32m";
    if (Code >= 300 && Code < 400) return "\033[34m";
    if (Code >= 400 && Code < 500) return "\033[31m";
    if (Code >= 500)               return "\033[31m";
    return "\033[2m";
}

static int SubHttpProbe(const char *Host, int Port, int UseHttps,
                         int *OutStatus, char *OutTitle, char *OutRedir, long *OutLat) {
    long Lat = 0;
    int Fd = TcpConnect(Host, Port, 3, &Lat);
    if (Fd < 0) return 0;

    char Req[512];
    snprintf(Req, sizeof(Req),
        "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: HTONSpider/%s\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n", Host, VersionStr);
    SendAll(Fd, (unsigned char *)Req, (int)strlen(Req));

    char Resp[4096]; memset(Resp, 0, sizeof(Resp)); int Total = 0;
    fd_set R; struct timeval Tv;
    while (Total < (int)sizeof(Resp) - 1) {
        FD_ZERO(&R); FD_SET(Fd, &R);
        Tv.tv_sec = 3; Tv.tv_usec = 0;
        if (select(Fd + 1, &R, NULL, NULL, &Tv) <= 0) break;
        int N = (int)recv(Fd, Resp + Total, sizeof(Resp) - Total - 1, 0);
        if (N <= 0) break;
        Total += N;
    }
    close(Fd);
    if (Total < 10) return 0;

    int Status = 0;
    sscanf(Resp, "HTTP/%*s %d", &Status);
    if (OutStatus) *OutStatus = Status;
    if (OutLat)    *OutLat    = Lat;

    if (OutRedir) {
        char *Loc = strcasestr(Resp, "Location:");
        if (Loc) {
            Loc += 9; while (*Loc == ' ') Loc++;
            char *End = strchr(Loc, '\r'); if (!End) End = strchr(Loc, '\n');
            int L = End ? (int)(End - Loc) : 64;
            if (L > 255) L = 255;
            memcpy(OutRedir, Loc, L); OutRedir[L] = '\0';
        }
    }

    if (OutTitle) {
        char *TitleTag = strcasestr(Resp, "<title");
        if (TitleTag) {
            char *TStart = strchr(TitleTag, '>');
            if (TStart) {
                TStart++;
                char *TEnd = strcasestr(TStart, "</title>");
                if (TEnd) {
                    int L = (int)(TEnd - TStart);
                    if (L > 127) L = 127;
                    memcpy(OutTitle, TStart, L); OutTitle[L] = '\0';
                    TrimLine(OutTitle);
                }
            }
        }
    }
    (void)UseHttps;
    return Status > 0 ? 1 : 0;
}

static void *SubWorker(void *Arg) {
    SubWorkerArg *WA = (SubWorkerArg *)Arg;
    char Full[320];
    snprintf(Full, sizeof(Full), "%s.%s", WA->Prefix, WA->Domain);
    char IP[64] = {0};
    int Ok = (DnsResolveA(Full, IP, WA->DnsServer, WA->DnsTimeout2) == 0);

    if (Ok) {
        pthread_mutex_lock(WA->Lock);
        SubResult *R = &WA->Results[*WA->Found];
        snprintf(R->Full,   sizeof(R->Full),   "%s", Full);
        snprintf(R->Sub,    sizeof(R->Sub),    "%s", WA->Prefix);
        snprintf(R->Domain, sizeof(R->Domain), "%s", WA->Domain);
        snprintf(R->IP,     sizeof(R->IP),     "%s", IP);
        R->Alive    = 1;
        R->PortCount = 0;
        (*WA->Found)++;
        pthread_mutex_unlock(WA->Lock);

        if (WA->HttpProbe) {
            SubHttpProbe(Full, 80, 0,
                &R->HttpStatus, R->Title, R->Redirect, &R->HttpLatency);
            SubHttpProbe(Full, 443, 1,
                &R->HttpsStatus, NULL, NULL, NULL);
        }

        if (WA->CheckPortCount > 0) {
            for (int p = 0; p < WA->CheckPortCount && p < 8; p++) {
                long Lat = 0;
                int Fd = TcpConnect(IP, WA->CheckPorts[p], 2, &Lat);
                if (Fd >= 0) {
                    close(Fd);
                    R->PortList[R->PortCount] = WA->CheckPorts[p];
                    R->PortOpen[R->PortCount] = 1;
                    R->PortCount++;
                }
            }
        }
    }

    pthread_mutex_lock(WA->Lock);
    (*WA->Count)++;
    pthread_mutex_unlock(WA->Lock);
    free(WA);
    return NULL;
}

static void ModuleSub(int Argc, char **Argv) {
    char Domain[256]       = {0};
    char DnsServer[64]     = "8.8.8.8";
    char WordlistFile[512] = {0};
    char ExportFile[512]   = {0};
    int  Threads           = 100;
    int  HttpProbe         = 0;
    int  FilterAliveOnly   = 0;
    int  FilterDeadOnly    = 0;
    int  CheckPorts[8]     = {0};
    int  CheckPortCount    = 0;

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h")) {
            printf("\n  %s%ssub%s  Subdomain Discovery\n\n", BD, CGreen, CR);
            printf("  %s%s-t%s %s<domain>%s      Target domain\n",             BD, CWhite, CR, CDim, CR);
            printf("  %s%s-w%s %s<file>%s         Custom wordlist file\n",     BD, CWhite, CR, CDim, CR);
            printf("  %s%s-s%s %s<server>%s       DNS server (def: 8.8.8.8)\n",BD, CWhite, CR, CDim, CR);
            printf("  %s%s-T%s %s<threads>%s      Threads (def: 100)\n",       BD, CWhite, CR, CDim, CR);
            printf("  %s%s-p%s %s<ports>%s        Port check e.g. 80,443,8080\n",BD, CWhite, CR, CDim, CR);
            printf("  %s%s-H%s                 HTTP probe (status, title)\n",  BD, CWhite, CR);
            printf("  %s%s-F%s %s<alive|dead>%s   Filter output\n",            BD, CWhite, CR, CDim, CR);
            printf("  %s%s-e%s %s<file>%s         Export results to file\n\n", BD, CWhite, CR, CDim, CR);
            printf("  %s%sExamples:%s\n", BD, CDim, CR);
            printf("  %shtonspider sub -t example.com -H -p 80,443 -F alive%s\n",     CDim, CR);
            printf("  %shtonspider sub -t example.com -e out.txt -w subs.txt%s\n\n",  CDim, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-t") && i+1<Argc) { snprintf(Domain,       sizeof(Domain),       "%s", Argv[++i]); }
        else if (!strcmp(Argv[i],"-s") && i+1<Argc) { snprintf(DnsServer,    sizeof(DnsServer),    "%s", Argv[++i]); }
        else if (!strcmp(Argv[i],"-w") && i+1<Argc) { snprintf(WordlistFile,  sizeof(WordlistFile), "%s", Argv[++i]); }
        else if (!strcmp(Argv[i],"-e") && i+1<Argc) { snprintf(ExportFile,    sizeof(ExportFile),   "%s", Argv[++i]); }
        else if (!strcmp(Argv[i],"-T") && i+1<Argc) { Threads = atoi(Argv[++i]); if (Threads<1) Threads=1; if (Threads>500) Threads=500; }
        else if (!strcmp(Argv[i],"-H"))              { HttpProbe = 1; }
        else if (!strcmp(Argv[i],"-F") && i+1<Argc) {
            i++;
            if      (!strcmp(Argv[i],"alive")) FilterAliveOnly = 1;
            else if (!strcmp(Argv[i],"dead"))  FilterDeadOnly  = 1;
        }
        else if (!strcmp(Argv[i],"-p") && i+1<Argc) {
            char PortBuf[64]; snprintf(PortBuf, sizeof(PortBuf), "%s", Argv[++i]);
            char *Tok = strtok(PortBuf, ",");
            while (Tok && CheckPortCount < 8) {
                CheckPorts[CheckPortCount++] = atoi(Tok);
                Tok = strtok(NULL, ",");
            }
        }
        else if (Argv[i][0] != '-' && !Domain[0]) { snprintf(Domain, sizeof(Domain), "%s", Argv[i]); }
    }

    if (!Domain[0]) { fprintf(stderr, "  %s%s[ERR]%s No domain. Use -t <domain>\n\n", BD, CRed, CR); return; }

    char DomainIP[64] = {0};
    DnsResolveA(Domain, DomainIP, DnsServer, 2);

    printf("\n  %s%sSUBDOMAIN DISCOVERY%s\n", BD, CGreen, CR);
    printf("  %s%starget%s  %s%s%s%s\n",    BD, CDim, CR, BD, CWhite, Domain, CR);
    if (DomainIP[0])
        printf("  %s%sip%s      %s%s%s%s\n", BD, CDim, CR, BD, CBlue, DomainIP, CR);
    printf("  %s%sdns%s     %s%s%s%s\n",    BD, CDim, CR, CDim, BD, DnsServer, CR);
    printf("  %s%sopts%s    threads=%s%s%d%s", BD, CDim, CR, BD, CWhite, Threads, CR);
    if (HttpProbe) printf("  %s%sHTTP-probe%s", BD, CGreen, CR);
    if (CheckPortCount > 0) {
        printf("  %s%sports=%s", BD, CDim, CR);
        for (int p = 0; p < CheckPortCount; p++)
            printf("%s%s%d%s%s", BD, CWhite, CheckPorts[p], CR, p<CheckPortCount-1?",":"");
    }
    if (FilterAliveOnly) printf("  %s%sfilter=alive%s", BD, CGreen, CR);
    if (FilterDeadOnly)  printf("  %s%sfilter=dead%s",  BD, CRed,   CR);
    if (ExportFile[0])   printf("  %s%sexport=%s%s%s",  BD, CDim, CR, CDim, ExportFile);
    printf("%s\n\n", CR);

    char **Words = NULL; int WordCount = 0; int WordMalloc = 0;
    if (WordlistFile[0]) {
        FILE *Fp = fopen(WordlistFile, "r");
        if (!Fp) { fprintf(stderr, "  %s%s[ERR]%s Cannot open: %s\n\n", BD, CRed, CR, WordlistFile); return; }
        int Cap = 4096;
        Words = (char **)malloc(sizeof(char *) * Cap);
        char Line[256];
        while (fgets(Line, sizeof(Line), Fp)) {
            TrimLine(Line); if (!Line[0] || Line[0]=='#') continue;
            if (WordCount >= Cap) { Cap *= 2; Words = (char **)realloc(Words, sizeof(char *)*Cap); }
            Words[WordCount++] = strdup(Line);
        }
        fclose(Fp); WordMalloc = 1;
        printf("  %s%s[+]%s Loaded %s%d%s words from %s%s%s\n\n", BD, CGreen, CR, BD, WordCount, CR, CDim, WordlistFile, CR);
    } else {
        while (SubWordlist[WordCount]) WordCount++;
        Words = (char **)SubWordlist;
        printf("  %s%s[+]%s Built-in wordlist %s(%d words)%s\n\n", BD, CGreen, CR, CDim, WordCount, CR);
    }

    int MaxResults = WordCount + 1;
    SubResult *Results = (SubResult *)calloc(MaxResults, sizeof(SubResult));
    pthread_mutex_t Lock = PTHREAD_MUTEX_INITIALIZER;
    volatile int DoneCount2 = 0, FoundCount = 0;

    pthread_t *Threads2 = (pthread_t *)malloc(sizeof(pthread_t) * WordCount);
    int Launched = 0, Pos = 0;

    while (Pos < WordCount && Running) {
        int End = Pos + Threads;
        if (End > WordCount) End = WordCount;

        for (int i = Pos; i < End; i++) {
            SubWorkerArg *WA = (SubWorkerArg *)malloc(sizeof(SubWorkerArg));
            WA->Domain         = Domain;
            WA->Prefix         = Words[i];
            WA->Results        = Results;
            WA->Index          = i;
            WA->Lock           = &Lock;
            WA->Count          = &DoneCount2;
            WA->Found          = &FoundCount;
            WA->DnsTimeout2    = 1;
            WA->HttpProbe      = HttpProbe;
            WA->CheckPortCount = CheckPortCount;
            for (int p = 0; p < CheckPortCount; p++) WA->CheckPorts[p] = CheckPorts[p];
            snprintf(WA->DnsServer, sizeof(WA->DnsServer), "%s", DnsServer);
            pthread_create(&Threads2[Launched], NULL, SubWorker, WA);
            Launched++;
        }

        for (int i = Pos; i < End; i++) {
            pthread_join(Threads2[i], NULL);
            int D = DoneCount2, F = FoundCount;
            float Pct = (float)D * 100.0f / (float)WordCount;
            printf("\r  %s%s[%s", BD, CDim, CR);
            int BW = 24;
            for (int b = 0; b < BW; b++)
                printf(b < (int)(Pct/100.0f*BW) ? "%s%s█%s" : "%s▒%s",
                    (b < (int)(Pct/100.0f*BW) ? BD : ""), CGreen, CR);
            printf("%s%s]%s %s%s%5.1f%%%s  %s%s%d/%d%s  %s%s+%d%s",
                BD, CDim, CR, BD, CWhite, Pct, CR,
                CDim, BD, D, WordCount, CR,
                BD, CGreen, F, CR);
            fflush(stdout);
        }
        Pos = End;
    }

    free(Threads2);
    printf("\r%80s\r", "");

    int TotalFound = FoundCount;
    int AliveCount2 = 0, DeadCount2 = 0;
    for (int i = 0; i < TotalFound; i++) {
        if (Results[i].Alive) AliveCount2++; else DeadCount2++;
    }

    printf("  %s%sSUBDOMAIN RESULTS%s  %s%s%s%s\n\n",
        BD, CGreen, CR, BD, CWhite, Domain, CR);

    for (int i = 0; i < TotalFound; i++) {
        SubResult *R = &Results[i];
        if (FilterAliveOnly && !R->Alive) continue;
        if (FilterDeadOnly  &&  R->Alive) continue;

        if (R->Alive) {
            printf("  %s%s%s%s  %s%s%s%s",
                BD, CGreen, R->Full, CR,
                BD, CBlue, R->IP, CR);

            if (HttpProbe) {
                if (R->HttpStatus > 0) {
                    const char *SC = StatusColor(R->HttpStatus);
                    printf("  %s%s[http:%d]%s", BD, SC, R->HttpStatus, CR);
                }
                if (R->HttpsStatus > 0) {
                    const char *SC = StatusColor(R->HttpsStatus);
                    printf("  %s%s[https:%d]%s", BD, SC, R->HttpsStatus, CR);
                }
                if (R->Title[0])
                    printf("  %s%s\"%s\"%s", CDim, BD, R->Title, CR);
                if (R->Redirect[0])
                    printf("  %s%s→%s%s", CDim, BD, R->Redirect, CR);
            }

            if (R->PortCount > 0) {
                printf("  %s%sports:%s", BD, CDim, CR);
                for (int p = 0; p < R->PortCount; p++)
                    printf("%s%s%d%s%s", BD, CGreen, R->PortList[p], CR, p<R->PortCount-1?",":"");
            }
        } else {
            printf("  %s%s%s%s  %s%sDEAD%s",
                CDim, BD, R->Full, CR, BD, CRed, CR);
        }
        printf("\n");
    }

    if (TotalFound == 0)
        printf("  %s%sNo subdomains found.%s\n", CDim, BD, CR);

    printf("\n  %s%schecked%s %s%s%d%s  %s%salive%s %s%s%d%s  %s%sdead%s %s%s%d%s\n\n",
        BD, CDim, CR, BD, CWhite, WordCount, CR,
        BD, CDim, CR, BD, CGreen, AliveCount2, CR,
        BD, CDim, CR, BD, CRed, DeadCount2, CR);

    if (ExportFile[0]) {
        FILE *Fp = fopen(ExportFile, "w");
        if (Fp) {
            time_t Now = time(NULL); struct tm *Tm = localtime(&Now); char TB[64];
            strftime(TB, sizeof(TB), "%Y-%m-%d %H:%M:%S", Tm);
            fprintf(Fp, "# HTONSpider sub  |  %s  |  %s\n", Domain, TB);
            fprintf(Fp, "# checked: %d  alive: %d  dead: %d\n#\n", WordCount, AliveCount2, DeadCount2);
            for (int i = 0; i < TotalFound; i++) {
                SubResult *R = &Results[i];
                if (FilterAliveOnly && !R->Alive) continue;
                if (FilterDeadOnly  &&  R->Alive) continue;
                if (R->Alive) {
                    fprintf(Fp, "%s  %s", R->Full, R->IP);
                    if (HttpProbe && R->HttpStatus  > 0) fprintf(Fp, "  http:%d",  R->HttpStatus);
                    if (HttpProbe && R->HttpsStatus > 0) fprintf(Fp, "  https:%d", R->HttpsStatus);
                    if (HttpProbe && R->Title[0])         fprintf(Fp, "  \"%s\"",   R->Title);
                    if (R->PortCount > 0) {
                        fprintf(Fp, "  ports:");
                        for (int p = 0; p < R->PortCount; p++)
                            fprintf(Fp, "%d%s", R->PortList[p], p<R->PortCount-1?",":"");
                    }
                    fprintf(Fp, "\n");
                } else {
                    fprintf(Fp, "# DEAD  %s\n", R->Full);
                }
            }
            fclose(Fp);
            printf("  %s%s[✓]%s Saved to %s%s%s%s\n\n", BD, CGreen, CR, BD, CDim, ExportFile, CR);
        } else {
            fprintf(stderr, "  %s%s[ERR]%s Cannot write: %s\n\n", BD, CRed, CR, ExportFile);
        }
    }

    free(Results);
    pthread_mutex_destroy(&Lock);
    if (WordMalloc) { for (int i = 0; i < WordCount; i++) free(Words[i]); free(Words); }
}

static const char *DirWordlist[] = {
    "admin","administrator","login","logout","dashboard","panel","cp","controlpanel",
    "api","api/v1","api/v2","api/v3","rest","graphql","swagger","docs","documentation",
    "index","index.php","index.html","index.htm","home","main","default",
    "upload","uploads","files","file","download","downloads","media","static","assets",
    "images","img","css","js","fonts","icons","thumbs","thumbnails",
    "backup","backups","bak","old","temp","tmp","cache","logs","log",
    "config","configuration","settings","setup","install","installer",
    "test","testing","demo","dev","development","staging","prod",
    "include","includes","lib","libs","library","vendor","node_modules",
    "src","source","app","application","core","system","modules","plugins",
    "user","users","account","accounts","profile","register","signup","signin",
    "wp-admin","wp-login.php","wp-content","wp-includes","wordpress",
    "phpmyadmin","pma","adminer","mysql","database","db",
    "shell","cmd","command","exec","execute","run",
    "robots.txt","sitemap.xml","sitemap","crossdomain.xml","xmlrpc.php",
    ".git",".gitignore",".env",".htaccess",".htpasswd","web.config",
    "readme","readme.txt","readme.md","changelog","license","Makefile",
    "server-status","server-info","phpinfo.php","info.php","php.ini",
    "cgi-bin","cgi","scripts","script","bin","exe","perl",
    "mail","webmail","smtp","email","newsletter","contact","feedback",
    "search","query","ajax","xhr","post","get","data","json","xml",
    "report","reports","stats","statistics","analytics","monitor","status",
    "health","ping","check","test.php","debug","trace","error",
    "private","secret","hidden","secure","ssl","tls","auth","oauth",
    "portal","intranet","internal","extranet","remote","vpn",
    "forum","board","community","support","help","faq","wiki",
    "blog","news","article","articles","post","posts","feed","rss",
    "shop","store","cart","checkout","order","orders","product","products",
    "payment","pay","billing","invoice","invoices","receipt",
    "gallery","photo","photos","video","videos","stream","live",
    "404","403","500","error","errors","maintenance","coming-soon",NULL
};

typedef struct {
    int    StatusCode;
    long   Latency;
    long   Bytes;
    char   Path[2048];
    char   ContentType[128];
    char   Location[512];
} DirResult;

typedef struct {
    char        Host[256];
    int         Port;
    char        Proto[8];
    char        BasePath[512];
    const char *Word;
    char        DnsServer[64];
    DirResult  *Results;
    int         Timeout;
    pthread_mutex_t *Lock;
    volatile int    *DoneRef;
    volatile int    *FoundRef;
} DirWorkerArg;

static int HttpHead(const char *Host, int Port, const char *Proto,
                     const char *Path, int Timeout,
                     int *OutStatus, long *OutBytes, char *OutCT, char *OutLoc) {
    long Lat = 0;
    int Fd = TcpConnect(Host, Port, Timeout, &Lat);
    if (Fd < 0) return -1;

    char Req[4096];
    snprintf(Req, sizeof(Req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: HTONSpider/%s\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n",
        Path, Host, VersionStr);
    SendAll(Fd, (unsigned char *)Req, (int)strlen(Req));

    char Resp[4096]; memset(Resp, 0, sizeof(Resp));
    int Total = 0;
    fd_set R; struct timeval Tv;
    while (Total < (int)sizeof(Resp) - 1) {
        FD_ZERO(&R); FD_SET(Fd, &R);
        Tv.tv_sec = Timeout; Tv.tv_usec = 0;
        if (select(Fd + 1, &R, NULL, NULL, &Tv) <= 0) break;
        int N = (int)recv(Fd, Resp + Total, sizeof(Resp) - Total - 1, 0);
        if (N <= 0) break;
        Total += N;
    }
    close(Fd);

    if (Total < 12) return -1;

    int Status = 0;
    sscanf(Resp, "HTTP/%*s %d", &Status);
    if (OutStatus) *OutStatus = Status;
    if (OutBytes)  *OutBytes  = Total;

    if (OutCT) {
        char *CT = strcasestr(Resp, "Content-Type:");
        if (CT) {
            CT += 13; while (*CT == ' ') CT++;
            char *End = strchr(CT, '\r'); if (!End) End = strchr(CT, '\n');
            int L = End ? (int)(End - CT) : 64;
            if (L > 127) L = 127;
            memcpy(OutCT, CT, L); OutCT[L] = '\0';
        }
    }

    if (OutLoc && (Status == 301 || Status == 302 || Status == 303 ||
                   Status == 307 || Status == 308)) {
        char *Loc = strcasestr(Resp, "Location:");
        if (Loc) {
            Loc += 9; while (*Loc == ' ') Loc++;
            char *End = strchr(Loc, '\r'); if (!End) End = strchr(Loc, '\n');
            int L = End ? (int)(End - Loc) : 256;
            if (L > 511) L = 511;
            memcpy(OutLoc, Loc, L); OutLoc[L] = '\0';
        }
    }
    (void)Proto;
    return Status;
}

static void *DirWorker(void *Arg) {
    DirWorkerArg *WA = (DirWorkerArg *)Arg;
    char FullPath[2048];
    snprintf(FullPath, sizeof(FullPath), "%.*s%.*s", 1023, WA->BasePath, 1023, WA->Word);

    int Status = 0; long Bytes = 0;
    char CT[128] = {0}, Loc[512] = {0};
    int Ret = HttpHead(WA->Host, WA->Port, WA->Proto, FullPath,
                       WA->Timeout, &Status, &Bytes, CT, Loc);

    pthread_mutex_lock(WA->Lock);
    (*WA->DoneRef)++;
    if (Ret > 0 && Status != 404 && Status != 0) {
        DirResult *R = &WA->Results[*WA->FoundRef];
        R->StatusCode = Status;
        R->Latency    = 0;
        R->Bytes      = Bytes;
        snprintf(R->Path,        sizeof(R->Path),        "%s", FullPath);
        snprintf(R->ContentType, sizeof(R->ContentType), "%s", CT);
        snprintf(R->Location,    sizeof(R->Location),    "%s", Loc);
        (*WA->FoundRef)++;
    }
    pthread_mutex_unlock(WA->Lock);
    free(WA);
    return NULL;
}

static void ModuleDir(int Argc, char **Argv) {
    char Url[512] = {0};
    char WordlistFile[512] = {0};
    int  Threads = 50;
    int  Timeout = 5;
    int  Depth   = 1;
    int  ShowAll = 0;

    for (int i = 0; i < Argc; i++) {
        if      (!strcmp(Argv[i],"-h")) {
            printf("\n  %s%sdir%s  Web Directory Discovery\n\n", BD, CGreen, CR);
            printf("  %s%s-u%s %s<url>%s         Target URL\n",           BD, CWhite, CR, CDim, CR);
            printf("  %s%s-w%s %s<file>%s         Wordlist file\n",        BD, CWhite, CR, CDim, CR);
            printf("  %s%s-T%s %s<threads>%s      Threads (def: 50)\n",   BD, CWhite, CR, CDim, CR);
            printf("  %s%s-t%s %s<sec>%s          Timeout (def: 5)\n",    BD, CWhite, CR, CDim, CR);
            printf("  %s%s-D%s %s<depth>%s        Crawl depth (def: 1)\n",BD, CWhite, CR, CDim, CR);
            printf("  %s%s-a%s                 Show 4xx responses too\n",  BD, CWhite, CR);
            printf("\n  %s%sExample:%s\n", BD, CDim, CR);
            printf("  %shtonspider dir -u http://example.com%s\n",         CDim, CR);
            printf("  %shtonspider dir -u http://example.com -D 2 -w list.txt%s\n\n", CDim, CR);
            return;
        }
        else if (!strcmp(Argv[i],"-u") && i+1<Argc) { snprintf(Url,         sizeof(Url),         "%s", Argv[++i]); }
        else if (!strcmp(Argv[i],"-w") && i+1<Argc) { snprintf(WordlistFile, sizeof(WordlistFile), "%s", Argv[++i]); }
        else if (!strcmp(Argv[i],"-T") && i+1<Argc) { Threads = atoi(Argv[++i]); if (Threads < 1) Threads = 1; if (Threads > 200) Threads = 200; }
        else if (!strcmp(Argv[i],"-t") && i+1<Argc) { Timeout = atoi(Argv[++i]); }
        else if (!strcmp(Argv[i],"-D") && i+1<Argc) { Depth   = atoi(Argv[++i]); if (Depth < 1) Depth = 1; if (Depth > 5) Depth = 5; }
        else if (!strcmp(Argv[i],"-a"))              { ShowAll = 1; }
        else if (Argv[i][0] != '-' && !Url[0])      { snprintf(Url, sizeof(Url), "%s", Argv[i]); }
    }

    if (!Url[0]) { fprintf(stderr, "  %s%s[ERR]%s No URL. Use -u <url>\n\n", BD, CRed, CR); return; }

    if (strncmp(Url, "http", 4) != 0) {
        char Tmp[520]; snprintf(Tmp, sizeof(Tmp), "http://%.510s", Url);
        snprintf(Url, sizeof(Url), "%.511s", Tmp);
    }

    char Proto[8] = "http", Host[256] = {0}, BasePath[512] = "/";
    int  Port = 80;
    char *Sl = strstr(Url, "://");
    if (Sl) {
        size_t PL = (size_t)(Sl - Url); if (PL < 8) { memcpy(Proto, Url, PL); Proto[PL] = '\0'; }
        Sl += 3;
    } else Sl = Url;
    if (strcasecmp(Proto, "https") == 0) Port = 443;
    char *PS = strchr(Sl, '/');
    if (PS) {
        snprintf(BasePath, sizeof(BasePath), "%s", PS);
        size_t HL = (size_t)(PS - Sl); if (HL >= sizeof(Host)) HL = sizeof(Host) - 1;
        memcpy(Host, Sl, HL); Host[HL] = '\0';
    } else {
        snprintf(Host, sizeof(Host), "%.*s", (int)(sizeof(Host) - 1), Sl);
    }
    char *CP = strchr(Host, ':'); if (CP) { Port = atoi(CP + 1); *CP = '\0'; }
    if (BasePath[strlen(BasePath) - 1] != '/') strncat(BasePath, "/", sizeof(BasePath) - strlen(BasePath) - 1);

    char IP[64] = {0}; ResolveStr(Host, IP, sizeof(IP));

    printf("\n  %s%sDIR DISCOVERY%s\n", BD, CGreen, CR);
    printf("  %s%starget%s   %s%s%s://%s:%d%s%s%s\n", BD, CDim, CR, BD, CWhite, Proto, Host, Port, BasePath, CR, "");
    if (IP[0]) printf("  %s%sip%s       %s%s%s%s\n", BD, CDim, CR, BD, CBlue, IP, CR);
    printf("  %s%sdepth%s    %s%s%d%s  %s%sthreads%s %s%s%d%s  %s%stimeout%s %s%s%ds%s\n\n",
        BD, CDim, CR, BD, CWhite, Depth, CR,
        BD, CDim, CR, BD, CWhite, Threads, CR,
        BD, CDim, CR, BD, CWhite, Timeout, CR);

    char **Words = NULL; int WordCount = 0; int WordMalloc = 0;
    if (WordlistFile[0]) {
        FILE *Fp = fopen(WordlistFile, "r");
        if (!Fp) { fprintf(stderr, "  %s%s[ERR]%s Cannot open: %s\n\n", BD, CRed, CR, WordlistFile); return; }
        int Cap = 4096;
        Words = (char **)malloc(sizeof(char *) * Cap);
        char Line[256];
        while (fgets(Line, sizeof(Line), Fp)) {
            TrimLine(Line); if (!Line[0] || Line[0] == '#') continue;
            if (WordCount >= Cap) { Cap *= 2; Words = (char **)realloc(Words, sizeof(char *) * Cap); }
            Words[WordCount++] = strdup(Line);
        }
        fclose(Fp); WordMalloc = 1;
        printf("  %s%s[+]%s Loaded %s%d%s words from %s%s%s\n\n", BD, CGreen, CR, BD, WordCount, CR, CDim, WordlistFile, CR);
    } else {
        while (DirWordlist[WordCount]) WordCount++;
        Words = (char **)DirWordlist;
        printf("  %s%s[+]%s Built-in wordlist %s(%d paths)%s\n\n", BD, CGreen, CR, CDim, WordCount, CR);
    }

    int MaxRes = WordCount * Depth + 1;
    DirResult *Results = (DirResult *)calloc(MaxRes, sizeof(DirResult));
    pthread_mutex_t Lock = PTHREAD_MUTEX_INITIALIZER;
    volatile int DirDone = 0, DirFound = 0;

    char *CurrentPaths[8]; int PathCount = 0;
    CurrentPaths[PathCount++] = strdup(BasePath);

    for (int D = 0; D < Depth && Running; D++) {
        if (PathCount == 0) break;
        char *ScanPath = CurrentPaths[0];

        printf("  %s%s[depth %d]%s  %s%s%s\n\n", BD, CDim, D + 1, CR, CDim, ScanPath, CR);
        DirDone = 0;

        pthread_t *Thr = (pthread_t *)malloc(sizeof(pthread_t) * WordCount);
        int Launched = 0, Active = 0;

        for (int i = 0; i < WordCount && Running; i++) {
            while (Active >= Threads) {
                usleep(3000);
                pthread_mutex_lock(&Lock);
                Active = Launched - DirDone;
                pthread_mutex_unlock(&Lock);
            }
            DirWorkerArg *WA = (DirWorkerArg *)malloc(sizeof(DirWorkerArg));
            snprintf(WA->Host,     sizeof(WA->Host),     "%s", Host);
            snprintf(WA->Proto,    sizeof(WA->Proto),    "%s", Proto);
            snprintf(WA->BasePath, sizeof(WA->BasePath), "%s", ScanPath);
            WA->Port    = Port;
            WA->Word    = Words[i];
            WA->Timeout = Timeout;
            WA->Results = Results;
            WA->Lock    = &Lock;
            WA->DoneRef = &DirDone;
            WA->FoundRef= &DirFound;
            pthread_create(&Thr[Launched], NULL, DirWorker, WA);
            Launched++; Active++;

            pthread_mutex_lock(&Lock);
            int Dn = DirDone, Fn = DirFound;
            pthread_mutex_unlock(&Lock);
            float Pct = (float)Dn * 100.0f / (float)WordCount;
            printf("\r  %s%s[%s", BD, CDim, CR);
            int BW = 26;
            for (int b = 0; b < BW; b++)
                printf(b < (int)(Pct / 100.0f * BW) ? "%s%s█%s" : "%s▒%s",
                    (b < (int)(Pct / 100.0f * BW) ? BD : ""), CGreen, CR);
            printf("%s%s]%s %s%s%5.1f%%%s  %s%s%d/%d%s  %s%sfound: %d%s",
                BD, CDim, CR, BD, CWhite, Pct, CR,
                CDim, BD, Dn, WordCount, CR,
                BD, CGreen, Fn, CR);
            fflush(stdout);
        }

        for (int i = 0; i < Launched; i++) pthread_join(Thr[i], NULL);
        free(Thr);
        printf("\r%80s\r", "");
        free(ScanPath);
        PathCount = 0;
    }

    int TotalFound = DirFound;
    printf("  %s%sDIR RESULTS%s  %s%s%s://%s:%d%s\n\n",
        BD, CGreen, CR, BD, CWhite, Proto, Host, Port, CR);

    for (int i = 0; i < TotalFound; i++) {
        DirResult *R = &Results[i];
        if (!ShowAll && R->StatusCode >= 400 && R->StatusCode < 500) continue;
        const char *SC = StatusColor(R->StatusCode);
        printf("  %s%s[%d]%s  %s%s%s%s",
            BD, SC, R->StatusCode, CR,
            BD, CGreen, R->Path, CR);
        if (R->Location[0])
            printf("  %s%s→ %s%s", CDim, BD, R->Location, CR);
        printf("\n");
    }

    if (TotalFound == 0 || (!ShowAll && TotalFound > 0)) {
        int Shown = 0;
        for (int i = 0; i < TotalFound; i++) {
            DirResult *R = &Results[i];
            if (R->StatusCode >= 200 && R->StatusCode < 400) Shown++;
        }
        if (Shown == 0 && !ShowAll)
            printf("  %s%sNo accessible paths found. Try -a to show 4xx.%s\n", CDim, BD, CR);
    }

    printf("\n  %s%schecked%s %s%s%d%s  %s%sfound%s %s%s%d%s  %s%sdepth%s %s%s%d%s\n\n",
        BD, CDim, CR, BD, CWhite, WordCount * Depth, CR,
        BD, CDim, CR, BD, CGreen, TotalFound, CR,
        BD, CDim, CR, BD, CWhite, Depth, CR);

    free(Results);
    pthread_mutex_destroy(&Lock);
    if (WordMalloc) { for (int i = 0; i < WordCount; i++) free(Words[i]); free(Words); }
}

int main(int Argc, char **Argv) {
    signal(SIGINT,SigHandler);signal(SIGTERM,SigHandler);
    if(Argc<2||!strcmp(Argv[1],"-h")||!strcmp(Argv[1],"help")||!strcmp(Argv[1],"--help")){PrintMainHelp(Argv[0]);return 0;}
    char *Mod=Argv[1];int MAc=Argc-2;char **MAv=Argv+2;
    if     (!strcmp(Mod,"proxy")) ModuleProxy(MAc,MAv);
    else if(!strcmp(Mod,"scan"))  ModuleScan(MAc,MAv);
    else if(!strcmp(Mod,"ping"))  ModulePing(MAc,MAv);
    else if(!strcmp(Mod,"trace")) ModuleTrace(MAc,MAv);
    else if(!strcmp(Mod,"dns"))   ModuleDns(MAc,MAv);
    else if(!strcmp(Mod,"whois")) ModuleWhois(MAc,MAv);
    else if(!strcmp(Mod,"http"))  ModuleHTTP(MAc,MAv);
    else if(!strcmp(Mod,"ifinfo"))ModuleIfinfo(MAc,MAv);
    else if(!strcmp(Mod,"banner"))ModuleBanner(MAc,MAv);
    else if(!strcmp(Mod,"subnet"))ModuleSubnet(MAc,MAv);
    else if(!strcmp(Mod,"ip"))    ModuleIP(MAc,MAv);
    else if(!strcmp(Mod,"sub"))   ModuleSub(MAc,MAv);
    else if(!strcmp(Mod,"dir"))   ModuleDir(MAc,MAv);
    else{fprintf(stderr,"  %s%s[ERR]%s Unknown module: %s\n\n",BD,CRed,CR,Mod);return 1;}
    return 0;
}
