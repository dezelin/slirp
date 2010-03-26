pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = slirp.pc

lib_LTLIBRARIES = libslirp.la

libslirpinclude_HEADERS = net_slirp.h
libslirpincludedir = $(includedir)/libslirp

NULL=

libslirp_la_SOURCES=		\
	bootp.c			\
	bootp.h			\
	cksum.h			\
	ctl.h			\
	debug.h			\
	icmp_var.h		\
	if.h			\
	ip.h			\
	ip_icmp.h		\
	mbuf.h			\
	misc.h			\
	sbuf.h			\
	slirp_common.h		\
	slirp_config.h		\
	socket.c		\
	socket.h		\
	tcp.h			\
	tcp_timer.h		\
	tcp_var.h		\
	tcpip.h			\
	tftp.h			\
	udp.h			\
	cksum.c			\
	debug.c			\
	if.c			\
	ip_icmp.c		\
	ip_input.c		\
	ip_output.c		\
	mbuf.c			\
	misc.c			\
	net_slirp.c		\
	sbuf.c			\
	tcp_input.c		\
	tcp_output.c		\
	tcp_subr.c		\
	tcp_timer.c		\
	udp.c			\
	$(NULL)
