
BIN	:= strongforth
SRC	:= stfmodule.c common.c device.c strongforth.c zforth.c base32.c hydrogen.c python_conf.c 

OBJS    := $(subst .c,.o, $(SRC))
DEPS    := $(subst .c,.d, $(SRC))

CC	:= $(CROSS)gcc

VPATH   := . ../linux ../core ./python
CFLAGS	+= -I. -I../linux -I../core -I/usr/lib/cryptoauthlib -I/usr/include/cryptoauthlib -I/usr/include/python3.8 -DSTF_DEVICE=1 -DSTF_LOGGING=1 -DZF_CONST_DICTIONARY=1
#CFLAGS  += -Os -g -std=c89 -ansi -pedantic -MMD
CFLAGS  += -fPIC -Wall -Wextra -Werror -Wno-unused-parameter -Wno-clobbered -Wno-unused-result
LDFLAGS	+= -g

LIBS	+= -lm -lcryptoauth -lusb-1.0 -lpython3.8

$(BIN): $(OBJS)
	$(CC) -shared $(LDFLAGS) -o stf.so $(OBJS) $(LIBS)

clean:
	rm -f $(BIN) $(OBJS) $(DEPS)
	rm -f stf.so

lint:
	lint -i /opt/flint/supp/lnt -i ..\\zforth -i src -w2 co-gcc.lnt \
		-e537 -e451 -e524 -e534 -e641 -e661 -e64 \
		$(SRC)

install:
	mkdir -p /usr/lib/python3.8/site-packages
	cp stf.so /usr/lib/python3.8/site-packages/stf.so

-include $(DEPS)

