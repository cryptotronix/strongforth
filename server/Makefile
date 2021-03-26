BIN	:= test
SRC	:= \
	common.c \
	strongforth.c \
	zforth.c \
	base32.c \
	uECC.c \
	hydrogen.c \
	server.c \
	test.c

OBJS    := $(subst .c,.o, $(SRC))
DEPS    := $(subst .c,.d, $(SRC))

CC	:= $(CROSS)gcc

VPATH   := ../lib/core
CFLAGS	+= -I. -I../lib/core -I/usr/lib/cryptoauthlib -I/usr/include/cryptoauthlib -DSTF_SERVER=1

#CFLAGS  += -Os -g -std=c89 -ansi -pedantic -MMD
CFLAGS  += -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -Wno-clobbered -Wno-unused-result
LDFLAGS	+= -fsanitize=address -g

LIBS	+= -lm -lcryptoauth

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f $(BIN) $(OBJS) $(DEPS)

lint:
	lint -i /opt/flint/supp/lnt -i ..\\zforth -i src -w2 co-gcc.lnt \
		-e537 -e451 -e524 -e534 -e641 -e661 -e64 \
		$(SRC)

-include $(DEPS)
