CC = gcc

CFLAGS = -fvisibility=hidden -fPIC -DPIC -Wall -Wno-sign-compare -Werror
LDFLAGS = -fPIC
TARGET = RELEASE

ifeq ($(TARGET),DEBUG)
	CFLAGS += -g -O0
	TARGETNAME = debug
else ifeq ($(TARGET),RELEASE)
	CFLAGS += -g -O3
	TARGETNAME = release
else
	TARGETNAME = $(error Invalid TARGET. Use DEBUG or RELEASE)
endif

HEADERNAME = net_slirp.h
LIBNAME = libslirp.so
PCNAME = slirp.pc

BIN = $(addprefix $(TARGETNAME)/, libslirp.so)

INCLUDEDIR = /usr/include/libslirp
LIBDIR = /usr/lib64
PKGCONFIGDIR = /usr/lib64/pkgconfig

SRCS =\
	bootp.c\
	cksum.c\
	debug.c\
	if.c\
	ip_icmp.c\
	ip_input.c\
	ip_output.c\
	mbuf.c\
	misc.c\
	sbuf.c\
	net_slirp.c\
	tcp_input.c\
	tcp_output.c\
	tcp_subr.c\
	tcp_timer.c\
	udp.c\
    socket.c\
    $(NULL)

TMP = $(SRCS:.c=.o)
OBJ = $(addprefix $(TARGETNAME)/, $(TMP))

STATIC_LIBS = 
DYNAMIC_LIBS =

LIBS = -Wl,-Bstatic $(addprefix -l, $(STATIC_LIBS)) -Wl,-Bdynamic $(addprefix -l, $(DYNAMIC_LIBS))

all : $(BIN) link

$(BIN) : $(TARGETNAME) $(OBJ)
	$(CC) -shared $(LDFLAGS) -o $(BIN) $(OBJ) $(LIBS)

link : $(BIN)
	rm -f $(LIBNAME)
	ln -s $(BIN)

MAKEDEPEND = $(CC) -M $(CFLAGS) -o $(addprefix $(TARGETNAME)/,.$*.dep.tmp) $<

$(addprefix $(TARGETNAME)/, %.o) : %.c Makefile
	@$(MAKEDEPEND) && \
	cp $(addprefix $(TARGETNAME)/, .$*.dep.tmp) $(addprefix $(TARGETNAME)/, .$*.dep) && \
	sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
	    -e '/^$$/ d' -e 's/$$/ :/' < $(addprefix $(TARGETNAME)/,.$*.dep.tmp) >> $(addprefix $(TARGETNAME)/,.$*.dep) && \
	sed -i '1 s/^\(.\)/$(TARGETNAME)\/\1/' $(addprefix $(TARGETNAME)/, .$*.dep) && \
	rm -f $(addprefix $(TARGETNAME)/,.$*.dep.tmp)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -f $(TARGETNAME)/*.o $(TARGETNAME)/.*.dep $(TARGETNAME)/.*.dep.tmp $(BIN)

$(TARGETNAME):
	@mkdir -p $(TARGETNAME)

-include $(patsubst %.c, $(TARGETNAME)/.%.dep, $(SRCS))

install:
	cp $(LIBNAME) $(LIBDIR)
	cp $(HEADERNAME) $(INCLUDEDIR)
	cp $(PCNAME) $(PKGCONFIGDIR)
uninstall:
	rm -f  $(LIBDIR)/$(LIBNAME)
	rm -f $(INCLUDEDIR)/$(HEADERNAME)
	rm -f $(PKGCONFIGDIR)/$(PCNAME)
