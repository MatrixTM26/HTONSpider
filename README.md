# HTONSpider

A networking toolkit for analize, trace, and filter active proxies

### Compile

```bash
gcc -O2 -Wall -o htonspider htonspider.c -lpthread
```

### Usage Example

```bash
./htonspider -L Proxies.txt -P auto -E -F alive -T 1000 -v -t 5
```
