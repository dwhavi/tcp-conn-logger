# tcp-conn-logger

리눅스에서 원격 주소가 특정 IP 와 일치하는 TCP 소켓/접속을 감지해서 로그로 남기는 프로그램입니다.
root 권한 없이 동작하고, 외부 라이브러리 없이 libc 만 사용합니다.

## 동작 원리

- `/proc/net/tcp`, `/proc/net/tcp6` 를 주기적으로 폴링합니다 (기본 1초).
- 지정한 대상 IP 와 일치하는 원격 주소의 접속을 찾습니다.
- 소켓 inode 기준으로 새 접속만 로그합니다 (같은 접속 반복 로그 없음, TTL 1시간).
- `/proc/<pid>/fd` 를 뒤져서 접속을 연 프로세스의 PID 와 이름을 같이 기록합니다.

## 빌드

```sh
make        # 또는: gcc -std=c11 -O2 -Wall -Wextra -o tcp-conn-logger tcp-conn-logger.c
```

## 실행

```sh
# 203.0.113.10 으로의 접속만 감지, 500ms 폴링
./tcp-conn-logger -t 203.0.113.10 -i 500

# 여러 대상 IP
./tcp-conn-logger -t 203.0.113.10 -t 8.8.8.8 -l /var/log/connwatch.log

# 대상을 지정하지 않으면 모든 TCP 접속을 로그
./tcp-conn-logger
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-t, --target IP` | 감지할 대상 IP (여러 번 지정 가능, 최대 64개, IPv4/IPv6) | (없음 = 전체) |
| `-i, --interval MS` | 폴링 주기 (밀리초) | 1000 |
| `-l, --log PATH` | 로그 파일 경로 | ./tcp-conn-logger.log |
| `-h, --help` | 도움말 | |

종료는 `Ctrl+C` (또는 `SIGTERM`). 종료 시 STOP 로그를 남깁니다.

## 로그 예시

```
[2026-10-29 09:10:34] START targets=1 interval_ms=200
[2026-10-29 09:10:34]   target[0] = 127.0.0.1
[2026-10-29 09:10:35] NEW_CONN remote=127.0.0.1:9999 local=127.0.0.1:47462 state=ESTABLISHED pid=1962 proc=python3 inode=14647
[2026-10-29 09:10:36] STOP
```

## 참고

- 다른 사용자 소유 프로세스는 권한 때문에 PID/이름을 못 가져올 수 있습니다 (`pid=-1 proc=-`). 시스템 전체를 보려면 root 로 실행하세요.
- 로그 파일은 append 모드로 열리고 매 줄 즉시 flush 됩니다. 로테이션이 필요하면 logrotate 를 사용하세요.
- **방향(아웃바운드/인바운드) 구분 한계**: `/proc/net/tcp` 목록만으로는 내가 먼저 건 접속과 상대가 걸어와 LISTEN 소켓이 accept 한 접속을 구분할 수 없습니다. LISTEN 상태 소켓은 걸러내지만, 이미 성립된 인바운드 접속도 원격 IP 가 대상과 일치하면 로그됩니다.
- localhost(127.0.0.1) 를 대상으로 지정하면 접속의 양쪽 끝이 모두 잡혀서 2줄이 로그됩니다. 실제 테스트에서도 클라이언트 측과 서버(accept) 측 소켓이 각각 1줄씩 기록됐습니다.

## 라이선스

MIT
