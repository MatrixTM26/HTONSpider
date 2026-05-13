# HTONSpider

A networking toolkit for analize, trace, and filter active proxies

### Installation and Usage

```bash
git clone https://github.com/MatrixTM26/HTONSpider.git
cd HTONSpider
```

### Compile

```bash
gcc -O2 -Wall -o htonspider htonspider.c -lpthread -lm
```

### Usage Example

**Proxy Check**

```bash
./htonspider -L Proxies.txt -P auto -E -F alive -T 1000 -v -t 5
```

```bash
./htonspider -s google.com -P <socket type: AUTO | HTTP | SOCKS4 | SOCKS5> -E <export filename> -F <filter type: alive | dead> -T <thread count> -v <verbose> -t <timeout>
```

**DNS Record Check**

```bash
./htonspider dns google.com -s 1.1.1.1
```

**Ping**

```bash
./htonspider ping google.com
```

**Trace**

```bash
./htonspider trace google.com
```

**Whois**

```bash
./htonspider whois google.com
```

**Subnet**

```bash
./htonspider subnet 172.0.0.0/24
```

