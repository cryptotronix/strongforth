TARGET_LIB := libstrongforthserver.so
LIB_SRC	:= common.c \
	strongforth.c \
	zforth.c \
	base32.c \
	uECC.c \
	hydrogen.c \
	server.c

TEST_BIN := stf_server_test
BIN_SRC	:= test.c

OBJS    := $(LIB_SRC:.c=.o)
DEPS    := $(LIB_SRC:.c=.d)

CC	:= $(CROSS)gcc

LIBS	+= -lm -lcryptoauth

VPATH   := ../lib/core
CFLAGS	+= -I. -I../lib/core -I/usr/lib/cryptoauthlib -I/usr/include/cryptoauthlib -fPIC -DSTF_SERVER=1 -DSTF_LOGGING=1

#CFLAGS  += -Os -g -std=c89 -ansi -pedantic -MMD
CFLAGS  += -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -Wno-clobbered -Wno-unused-result
LDFLAGS	+= -fsanitize=address -g -shared $(LIBS)

.PHONY: all

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(DEPS): %.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

.PHONY: clean
clean:
	rm -f $(TARGET_LIB) $(OBJS) $(DEPS)

lint:
	lint -i /opt/flint/supp/lnt -i ..\\zforth -i src -w2 co-gcc.lnt \
		-e537 -e451 -e524 -e534 -e641 -e661 -e64 \
		$(SRC)

-include $(DEPS)
