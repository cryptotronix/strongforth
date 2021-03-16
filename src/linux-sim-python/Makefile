
BIN	:= zforth
SRC	:= sys.c zforth.c base32.c uECC.c sfmodule.c

OBJS    := $(subst .c,.o, $(SRC))
DEPS    := $(subst .c,.d, $(SRC))

CC	:= $(CROSS)gcc

VPATH   := ../zforth
CFLAGS	+= -I. -I../zforth -I/usr/include/python3.8
#CFLAGS  += -Os -g -std=c89 -ansi -pedantic -MMD
CFLAGS  += -fPIC -Wall -Wextra -Werror -Wno-unused-parameter -Wno-clobbered -Wno-unused-result
LDFLAGS	+= -g

LIBS	+= -lm -lpython3.8

$(BIN): $(OBJS)
	$(CC) -shared $(LDFLAGS) -o sf.so $(OBJS) $(LIBS)

clean:
	rm -f $(BIN) $(OBJS) $(DEPS) sf.so

lint:
	lint -i /opt/flint/supp/lnt -i ..\\zforth -i src -w2 co-gcc.lnt \
		-e537 -e451 -e524 -e534 -e641 -e661 -e64 \
		$(SRC)

-include $(DEPS)

