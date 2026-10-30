# tcp-conn-logger 빌드 파일
CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra
TARGET   = tcp-conn-logger

all: $(TARGET)

$(TARGET): tcp-conn-logger.c
	$(CC) $(CFLAGS) -o $@ $<

# systemd 에 설치하거나 로그 경로를 바꿀 때 참고용
install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/bin/$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install clean
