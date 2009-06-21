/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp_subr.c	8.1 (Berkeley) 6/10/93
 * tcp_subr.c,v 1.5 1994/10/08 22:39:58 phk Exp
 */

/*
 * Changes and additions relating to SLiRP
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#define WANT_SYS_IOCTL_H
#include "tcp.h"
#include "if.h"
#include "slirp_common.h"
#include "cksum.h"
#include "misc.h"

/* patchable/settable parameters for tcp */
/* Don't do rfc1323 performance enhancements */
#define TCP_DO_RFC1323 0

/*
 * Tcp initialization
 */
void
tcp_init()
{
	tcp_iss = 1;		/* wrong */
	tcb.so_next = tcb.so_prev = &tcb;
}


/*
 * Create template to be used to send tcp packets on a connection.
 * Call after host entry created, fills
 * in a skeletal tcp/ip header, minimizing the amount of work
 * necessary when the connection is used.
 */
/* struct tcpiphdr * */
void
tcp_template(tp)
	struct tcpcb *tp;
{
	struct socket *so = tp->t_socket;
	register struct tcpiphdr *n = &tp->t_template;

	n->ti_mbuf = NULL;
	n->ti_x1 = 0;
	n->ti_pr = IPPROTO_TCP;
	n->ti_len = htons(sizeof (struct tcpiphdr) - sizeof (struct ip));
	n->ti_src = so->so_faddr;
	n->ti_dst = so->so_laddr;
	n->ti_sport = so->so_fport;
	n->ti_dport = so->so_lport;

	n->ti_seq = 0;
	n->ti_ack = 0;
	n->ti_x2 = 0;
	n->ti_off = 5;
	n->ti_flags = 0;
	n->ti_win = 0;
	n->ti_sum = 0;
	n->ti_urp = 0;
}

/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == 0, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection tp->t_template.  If flags are given
 * then we send a message back to the TCP which originated the
 * segment ti, and discard the mbuf containing it and any other
 * attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 */
void
tcp_respond(tp, ti, m, ack, seq, flags)
	struct tcpcb *tp;
	register struct tcpiphdr *ti;
	register struct mbuf *m;
	tcp_seq ack, seq;
	int flags;
{
	register int tlen;
	int win = 0;

	DEBUG_CALL("tcp_respond");
	DEBUG_ARG("tp = %lx", (long)tp);
	DEBUG_ARG("ti = %lx", (long)ti);
	DEBUG_ARG("m = %lx", (long)m);
	DEBUG_ARG("ack = %u", ack);
	DEBUG_ARG("seq = %u", seq);
	DEBUG_ARG("flags = %x", flags);

	if (tp)
		win = sbspace(&tp->t_socket->so_rcv);
	if (m == 0) {
		if ((m = m_get()) == NULL)
			return;
#ifdef TCP_COMPAT_42
		tlen = 1;
#else
		tlen = 0;
#endif
		m->m_data += IF_MAXLINKHDR;
		*mtod(m, struct tcpiphdr *) = *ti;
		ti = mtod(m, struct tcpiphdr *);
		flags = TH_ACK;
	} else {
		/*
		 * ti points into m so the next line is just making
		 * the mbuf point to ti
		 */
		m->m_data = (caddr_t)ti;

		m->m_len = sizeof (struct tcpiphdr);
		tlen = 0;
#define xchg(a,b,type) { type t; t=a; a=b; b=t; }
		xchg(ti->ti_dst.s_addr, ti->ti_src.s_addr, u_int32_t);
		xchg(ti->ti_dport, ti->ti_sport, u_int16_t);
#undef xchg
	}
	ti->ti_len = htons((u_short)(sizeof (struct tcphdr) + tlen));
	tlen += sizeof (struct tcpiphdr);
	m->m_len = tlen;

	ti->ti_mbuf = 0;
	ti->ti_x1 = 0;
	ti->ti_seq = htonl(seq);
	ti->ti_ack = htonl(ack);
	ti->ti_x2 = 0;
	ti->ti_off = sizeof (struct tcphdr) >> 2;
	ti->ti_flags = flags;
	if (tp)
		ti->ti_win = htons((u_int16_t) (win >> tp->rcv_scale));
	else
		ti->ti_win = htons((u_int16_t)win);
	ti->ti_urp = 0;
	ti->ti_sum = 0;
	ti->ti_sum = cksum(m, tlen);
	((struct ip *)ti)->ip_len = tlen;

	if(flags & TH_RST)
	  ((struct ip *)ti)->ip_ttl = MAXTTL;
	else
	  ((struct ip *)ti)->ip_ttl = IPDEFTTL;

	(void) ip_output((struct socket *)0, m);
}

/*
 * Create a new TCP control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.
 */
struct tcpcb *
tcp_newtcpcb(so)
	struct socket *so;
{
	register struct tcpcb *tp;

	tp = (struct tcpcb *)malloc(sizeof(*tp));
	if (tp == NULL)
		return ((struct tcpcb *)0);

	memset((char *) tp, 0, sizeof(struct tcpcb));
	tp->seg_next = tp->seg_prev = (struct tcpiphdr*)tp;
	tp->t_maxseg = TCP_MSS;

	tp->t_flags = TCP_DO_RFC1323 ? (TF_REQ_SCALE|TF_REQ_TSTMP) : 0;
	tp->t_socket = so;

	/*
	 * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 2 * rttvar gives
	 * reasonable initial retransmit time.
	 */
	tp->t_srtt = TCPTV_SRTTBASE;
	tp->t_rttvar = TCPTV_SRTTDFLT << 2;
	tp->t_rttmin = TCPTV_MIN;

	TCPT_RANGESET(tp->t_rxtcur,
	    ((TCPTV_SRTTBASE >> 2) + (TCPTV_SRTTDFLT << 2)) >> 1,
	    TCPTV_MIN, TCPTV_REXMTMAX);

	tp->snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->t_state = TCPS_CLOSED;

	so->so_tcpcb = tp;

	return (tp);
}

/*
 * Drop a TCP connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
struct tcpcb *tcp_drop(struct tcpcb *tp, int err)
{
/* tcp_drop(tp, errno)
	register struct tcpcb *tp;
	int errno;
{
*/

	DEBUG_CALL("tcp_drop");
	DEBUG_ARG("tp = %lx", (long)tp);
	DEBUG_ARG("errno = %d", errno);

	if (TCPS_HAVERCVDSYN(tp->t_state)) {
		tp->t_state = TCPS_CLOSED;
		(void) tcp_output(tp);
		STAT(tcpstat.tcps_drops++);
	} else
		STAT(tcpstat.tcps_conndrops++);
/*	if (errno == ETIMEDOUT && tp->t_softerror)
 *		errno = tp->t_softerror;
 */
/*	so->so_error = errno; */
	return (tcp_close(tp));
}

/*
 * Close a TCP control block:
 *	discard all space held by the tcp
 *	discard internet protocol block
 *	wake up any sleepers
 */
struct tcpcb *
tcp_close(tp)
	register struct tcpcb *tp;
{
	register struct tcpiphdr *t;
	struct socket *so = tp->t_socket;
	register struct mbuf *m;

	DEBUG_CALL("tcp_close");
	DEBUG_ARG("tp = %lx", (long )tp);

	/* free the reassembly queue, if any */
	t = tcpfrag_list_first(tp);
	while (!tcpfrag_list_end(t, tp)) {
		t = tcpiphdr_next(t);
		m = tcpiphdr_prev(t)->ti_mbuf;
		remque(tcpiphdr2qlink(tcpiphdr_prev(t)));
		m_freem(m);
	}
	/* It's static */
/*	if (tp->t_template)
 *		(void) m_free(dtom(tp->t_template));
 */
/*	free(tp, M_PCB);  */
	free(tp);
	so->so_tcpcb = 0;
	soisfdisconnected(so);
	/* clobber input socket cache if we're closing the cached connection */
	if (so == tcp_last_so)
		tcp_last_so = &tcb;

    if (so->usr_so) {
        slirp_net_interface->close(slirp_net_interface, so->usr_so);
    }
	sbfree(&so->so_rcv);
	sbfree(&so->so_snd);
	sofree(so);
	STAT(tcpstat.tcps_closed++);
	return ((struct tcpcb *)0);
}

#ifdef notdef
void
tcp_drain()
{
	/* XXX */
}

/*
 * When a source quench is received, close congestion window
 * to one segment.  We will gradually open it again as we proceed.
 */
void
tcp_quench(i, errno)

	int errno;
{
	struct tcpcb *tp = intotcpcb(inp);

	if (tp)
		tp->snd_cwnd = tp->t_maxseg;
}

#endif /* notdef */

/*
 * TCP protocol interface to socket abstraction.
 */

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
void
tcp_sockclosed(tp)
	struct tcpcb *tp;
{

	DEBUG_CALL("tcp_sockclosed");
	DEBUG_ARG("tp = %lx", (long)tp);

	switch (tp->t_state) {

	case TCPS_CLOSED:
	case TCPS_LISTEN:
	case TCPS_SYN_SENT:
		tp->t_state = TCPS_CLOSED;
		tp = tcp_close(tp);
		break;

	case TCPS_SYN_RECEIVED:
	case TCPS_ESTABLISHED:
		tp->t_state = TCPS_FIN_WAIT_1;
		break;

	case TCPS_CLOSE_WAIT:
		tp->t_state = TCPS_LAST_ACK;
		break;
	}
/*	soisfdisconnecting(tp->t_socket); */
	if (tp && tp->t_state >= TCPS_FIN_WAIT_2)
		soisfdisconnected(tp->t_socket);
	if (tp)
		tcp_output(tp);
}

/*
 * Connect to a host on the Internet
 * Called by tcp_input
 * Only do a connect, the tcp fields will be set in tcp_input
 * return 0 if there's a result of the connect,
 * else return -1 means we're still connecting
 * The return value is almost always -1 since the socket is
 * nonblocking.  Connect returns after the SYN is sent, and does
 * not wait for ACK+SYN.
 */
int tcp_fconnect(so)
     struct socket *so;
{
  int ret=0;
  struct sockaddr_in addr;

  DEBUG_CALL("tcp_fconnect");
  DEBUG_ARG("so = %lx", (long )so);

    addr.sin_family = AF_INET;
    if ((so->so_faddr.s_addr & htonl(0xffffff00)) == special_addr.s_addr) {
      /* It's an alias */
      switch(ntohl(so->so_faddr.s_addr) & 0xff) {
        case CTL_DNS:
	        addr.sin_addr = dns_addr;
            printf("tcp_fconnect DNS not supported");
            exit(-1);
	        break;
        case CTL_ALIAS:
            addr.sin_addr = loopback_addr;
            printf("tcp_fconnect LOOPBACK not supported");
            exit(-1);
            break;
        default:
            addr.sin_addr = so->so_faddr; // should be part of the virtual netowk
            break;
      }
    } else {
        addr.sin_addr = so->so_faddr;
    }
    addr.sin_port = so->so_fport;

    DEBUG_MISC((dfd, " connect()ing, addr.sin_port=%d, "
		"addr.sin_addr.s_addr=%.16s\n",
		ntohs(addr.sin_port), inet_ntoa(addr.sin_addr)));
    /* We don't care what port we get */
    ret = slirp_net_interface->connect(slirp_net_interface, so->so_laddr, so->so_lport,
        addr.sin_addr, addr.sin_port, so, &so->usr_so);
    /*
     * If it's not in progress, it failed, so we just return 0,
     * without clearing SS_NOFDREF
     */
    soisfconnecting(so);

  return(ret);
}

/*
 * Attach a TCPCB to a socket.
 */
int
tcp_attach(so)
	struct socket *so;
{
	if ((so->so_tcpcb = tcp_newtcpcb(so)) == NULL)
	   return -1;

	insque(so, &tcb);

	return 0;
}


/*
 * Set the socket's type of service field
 */
static const struct tos_t tcptos[] = {
	  {0, 20, IPTOS_THROUGHPUT, 0},	/* ftp data */
	  {21, 21, IPTOS_LOWDELAY,  EMU_FTP},	/* ftp control */
	  {0, 23, IPTOS_LOWDELAY, 0},	/* telnet */
	  {0, 80, IPTOS_THROUGHPUT, 0},	/* WWW */
	  {0, 513, IPTOS_LOWDELAY, EMU_RLOGIN|EMU_NOCONNECT},	/* rlogin */
	  {0, 514, IPTOS_LOWDELAY, EMU_RSH|EMU_NOCONNECT},	/* shell */
	  {0, 544, IPTOS_LOWDELAY, EMU_KSH},		/* kshell */
	  {0, 543, IPTOS_LOWDELAY, 0},	/* klogin */
	  {0, 6667, IPTOS_THROUGHPUT, EMU_IRC},	/* IRC */
	  {0, 6668, IPTOS_THROUGHPUT, EMU_IRC},	/* IRC undernet */
	  {0, 7070, IPTOS_LOWDELAY, EMU_REALAUDIO }, /* RealAudio control */
	  {0, 113, IPTOS_LOWDELAY, EMU_IDENT }, /* identd protocol */
	  {0, 0, 0, 0}
};

u_int8_t
tcp_tos(so)
	struct socket *so;
{
    return 0;
#if 0 
	int i = 0;

	while(tcptos[i].tos) {
		if ((tcptos[i].fport && (ntohs(so->so_fport) == tcptos[i].fport)) ||
		    (tcptos[i].lport && (ntohs(so->so_lport) == tcptos[i].lport))) {
			return tcptos[i].tos;
		}
		i++;
	}

	return 0;
#endif 
}

int
tcp_emu(so, m)
	struct socket *so;
	struct mbuf *m;
{
    fprintf(stderr, "Error tcp_emu not supported");
    exit(-1);
}

int
tcp_ctl(so)
	struct socket *so;
{
    fprintf(stderr, "Error tcp_ctl not supported");
    exit(-1);
}

typedef struct __attribute__((packed)) TcpcbExportData {
    int16_t state;
    int16_t timer[TCPT_NTIMERS];
    int16_t rxtshift;
    int16_t rxtcur;
    int16_t dupacks;
    u_int16_t maxseg;
    char force;
    u_int16_t flags;

	u_int32_t	snd_una;
	u_int32_t	snd_nxt;
	u_int32_t	snd_up;
	u_int32_t	snd_wl1;
	u_int32_t	snd_wl2;
	u_int32_t	iss;
	u_int32_t snd_wnd;		

	u_int32_t rcv_wnd;	
	u_int32_t	rcv_nxt;	
	u_int32_t	rcv_up;			
	u_int32_t	irs;

    u_int32_t	rcv_adv;	
	u_int32_t	snd_max;

	u_int32_t snd_cwnd;		
	u_int32_t snd_ssthresh;

    int16_t   idle;	       
	int16_t	  rtt;
	u_int32_t rtseq;
	int16_t	  srtt;
	int16_t	  rttvar;
	u_int16_t rttmin;
	u_int32_t max_sndwnd;

	char	oobflags;
	char	iobc;

    u_int32_t	last_ack_sent;

    //	int16_t	softerror; // always 0
    // the current implementation of slirp doesn't support window scaling
    // and these field are always zero
    /* u_char	snd_scale;  
	u_char	rcv_scale;
	u_char	request_r_scale;
	u_char	requested_s_scale; */

    // the current implementation of slirp doesn't support timestamp
    // and these field are always zero
	/* u_int32_t	ts_recent;
	  u_int32_t	ts_recent_age; */
} TcpcbExportData;

typedef struct __attribute__((packed)) TcpSocketExportData {
    u_int32_t so_urgc;
    u_int8_t faddr[4];
    u_int8_t laddr[4];
    u_int16_t fport;
    u_int16_t lport;
    u_int8_t  iptos;
    u_char    type;
    u_int32_t state;

    int32_t syn_pack_offset; // assigned if the socket is during connections

    int32_t rcv_buf_offset; 
    int32_t snd_buf_offset;

    TcpcbExportData tcpcb;
    int32_t       reass_queue_offset; // offset to tcpSocketReassQueue
    char data[0];
} TcpSocketExportData;

typedef struct __attribute__((packed)) TcpMbufExportData {
    uint32_t size;
    uint32_t mbuf_offset; // the tcpip header starts before the mbuf data
    char data[0];
} TcpMbufExportData;

typedef struct __attribute__((packed)) SbufExportData {
    uint32_t reserved;
    uint32_t size;
    char data[0]; 
} SbufExportData; 

typedef struct __attribute__((packed)) ReassQueueExportData {
    uint32_t num_packets;
    int32_t packets[0]; // array of offsets
} ReassQueueExportData;

#define EXPORT_NULL_OFFSET -1

static inline uint32_t __get_tcpip_pckt_size(struct tcpiphdr *ti) 
{
    struct mbuf *m = dtom(ti);
    return ((unsigned long)m->m_data - (unsigned long)ti + m->m_len);
}

static void __export_tcpip_pckt(struct tcpiphdr *ti, TcpMbufExportData *mbuf_data)
{
    struct mbuf *m = dtom(ti);
    mbuf_data->size = __get_tcpip_pckt_size(ti);
    mbuf_data->mbuf_offset = mbuf_data->size - m->m_len; 
    memcpy(mbuf_data->data, ti, mbuf_data->size);
}

static inline struct tcpiphdr *__restore_tcpip_pckt(TcpMbufExportData *exp_mbuf) 
{
    struct mbuf *m = m_get(); 
    struct tcpiphdr *ti;
    if (!m ) {
        return NULL;
    }

    if (M_FREEROOM(m) < (exp_mbuf->size + sizeof(struct qlink))) {
        m_inc(m, exp_mbuf->size + sizeof(struct qlink));
    }
    m->m_data += sizeof(struct qlink);
    m->m_len = exp_mbuf->size;

    memcpy(m->m_data, exp_mbuf->data, exp_mbuf->size);
    ti = mtod(m, struct tcpiphdr *);
    ti->ti_mbuf = m;

    m->m_data += exp_mbuf->mbuf_offset;
    m->m_len  -= exp_mbuf->mbuf_offset;

    return ti;
}

static inline void __export_sbuf(struct sbuf *sbuf, SbufExportData *exp_sbuf) 
{
    exp_sbuf->reserved = sbuf->sb_datalen;
    exp_sbuf->size = sbuf->sb_cc;

    sbcopy(sbuf, 0, sbuf->sb_cc, exp_sbuf->data);
}

static inline void __restore_sbuf(SbufExportData *exp_sbuf, struct sbuf *sbuf)
{
    sbreserve(sbuf, exp_sbuf->reserved);
    memcpy(sbuf->sb_data, exp_sbuf->data, exp_sbuf->size);
    sbuf->sb_cc = exp_sbuf->size;
    sbuf->sb_rptr = sbuf->sb_data;

    if (sbuf->sb_cc == sbuf->sb_datalen) {
        sbuf->sb_wptr = sbuf->sb_data;
    } else {
        sbuf->sb_wptr = sbuf->sb_data + sbuf->sb_cc;
    }

   
}

// returns how many bytes were written to export_data->data
static int __tcp_socket_export_socket_data(struct socket *so, TcpSocketExportData *export_data, 
                                    int data_offset)
{
    char *data;
    export_data->so_urgc = so->so_urgc;
    memcpy(export_data->faddr, &so->so_faddr.s_addr, 4);
    memcpy(export_data->laddr, &so->so_laddr.s_addr, 4);
    export_data->fport = so->so_fport;
    export_data->lport = so->so_lport;
    export_data->iptos = so->so_iptos;
    export_data->type = so->so_type;
    export_data->state = so->so_state;

    data  = export_data->data + data_offset;
    if ((so->so_state & SS_ISFCONNECTING) && so->so_ti) {
        __export_tcpip_pckt(so->so_ti, (TcpMbufExportData *)data);
        export_data->syn_pack_offset = data - export_data->data;
        data +=  (sizeof(TcpMbufExportData) + ((TcpMbufExportData *)data)->size);
    } else {
        export_data->syn_pack_offset = EXPORT_NULL_OFFSET;
    }


    if (so->so_rcv.sb_datalen) {
        __export_sbuf(&so->so_rcv, (SbufExportData *)data);
        export_data->rcv_buf_offset = data - export_data->data;
        data += (sizeof(SbufExportData) + ((SbufExportData *)data)->size);
    } else {
        export_data->rcv_buf_offset = EXPORT_NULL_OFFSET;
    }

    if (so->so_snd.sb_datalen) {
        __export_sbuf(&so->so_snd, (SbufExportData *)data);
        export_data->snd_buf_offset = data - export_data->data;
        data += (sizeof(SbufExportData) + ((SbufExportData *)data)->size);
    } else {
        export_data->rcv_buf_offset = EXPORT_NULL_OFFSET;
    }

    return (data - export_data->data + data_offset);
}


static struct socket* __tcp_socket_restore_socket_data(TcpSocketExportData *export_data) {
    struct socket *so = NULL;
 
    if ((so = socreate()) == NULL) {
        fprintf(stderr, "failed: creating socket\n");
        goto error;
    }

    // Creates the tcpcb and adds the socket to to the tcp sockets list.
    // Also sets the link from the tcpcp to the socket and vice versa
    if (tcp_attach(so) < 0) {
        fprintf(stderr, "faild: attach socket\n");
        goto error;
    }
    
    so->so_urgc = export_data->so_urgc;
    memcpy(&so->so_faddr.s_addr, export_data->faddr, 4);
    memcpy(&so->so_laddr.s_addr, export_data->laddr, 4);
    so->so_fport = export_data->fport;
    so->so_lport = export_data->lport;
    so->so_iptos = export_data->iptos;
    so->so_type = export_data->type;
    so->so_state = export_data->state;


    if (export_data->syn_pack_offset != EXPORT_NULL_OFFSET) {
        so->so_ti = __restore_tcpip_pckt((TcpMbufExportData *) (
            export_data->data + export_data->syn_pack_offset));

        if (!so->so_ti) {
            fprintf(stderr, "failed: restoring syn packet\n");
            goto error;
        }
        so->so_m = so->so_ti->ti_mbuf;
    }

    if (export_data->rcv_buf_offset != EXPORT_NULL_OFFSET) {
        __restore_sbuf((SbufExportData *)(
            export_data->data + export_data->rcv_buf_offset), &so->so_rcv);
    }

    if (export_data->snd_buf_offset != EXPORT_NULL_OFFSET) {
        __restore_sbuf((SbufExportData *)(
            export_data->data + export_data->snd_buf_offset), &so->so_snd);
    }
    return so;
error:
     if (so) {
         if (so->so_m) {
             m_free(so->so_m);
         }
         free(so);
     }
     return NULL;
}

static void __tcp_socket_export_tcpcb_data(struct tcpcb *tp, TcpcbExportData *export_data)
{
    int i;
    export_data->state = tp->t_state;
    for (i = 0; i < TCPT_NTIMERS; i++) {
        export_data->timer[i] = tp->t_timer[i];
    }
    export_data->rxtshift = tp->t_rxtshift;
    export_data->rxtcur = tp->t_rxtcur;
    export_data->dupacks = tp->t_dupacks;
    export_data->maxseg = tp->t_maxseg;
    export_data->force = tp->t_force;
    export_data->flags = tp->t_flags;

    export_data->snd_una = tp->snd_una;
    export_data->snd_nxt = tp->snd_nxt;
    export_data->snd_up = tp->snd_up;
    export_data->snd_wl1 = tp->snd_wl1;
    export_data->snd_wl2 = tp->snd_wl2;
    export_data->iss = tp->iss;
    export_data->snd_wnd = tp->snd_wnd;
    
    export_data->rcv_wnd = tp->rcv_wnd;
    export_data->rcv_nxt = tp->rcv_nxt;
    export_data->rcv_up = tp->rcv_up;
    export_data->irs = tp->irs;

    export_data->rcv_adv = tp->rcv_adv;
    export_data->snd_max = tp->snd_max;

    export_data->snd_cwnd = tp->snd_cwnd;
    export_data->snd_ssthresh = tp->snd_ssthresh;

    export_data->idle = tp->t_idle;
    export_data->rtt = tp->t_rtt;
    export_data->rtseq = tp->t_rtseq;
    export_data->srtt = tp->t_srtt;
    export_data->rttvar = tp->t_rttvar;
    export_data->rttmin = tp->t_rttmin;
    export_data->max_sndwnd = tp->max_sndwnd;

    export_data->oobflags = tp->t_oobflags;
    export_data->iobc = tp->t_iobc;
    
    export_data->last_ack_sent = tp->last_ack_sent;
}

static void __tcp_socket_restore_tcpcb_data(TcpcbExportData *export_data, struct tcpcb *tp)
{
    int i;

    tp->t_state = export_data->state;
    for (i = 0; i < TCPT_NTIMERS; i++) {
        tp->t_timer[i] = export_data->timer[i];
    }
    tp->t_rxtshift =  export_data->rxtshift; 
    tp->t_rxtcur = export_data->rxtcur;
    tp->t_dupacks = export_data->dupacks;
    tp->t_maxseg = export_data->maxseg;
    tp->t_force = export_data->force;
    tp->t_flags = export_data->flags;

    tp->snd_una = export_data->snd_una;
    tp->snd_nxt = export_data->snd_nxt;
    tp->snd_up = export_data->snd_up;
    tp->snd_wl1 = export_data->snd_wl1;
    tp->snd_wl2 = export_data->snd_wl2;
    tp->iss = export_data->iss;
    tp->snd_wnd = export_data->snd_wnd;

    tp->rcv_wnd = export_data->rcv_wnd;
    tp->rcv_nxt = export_data->rcv_nxt;
    tp->rcv_up = export_data->rcv_up;
    tp->irs = export_data->irs;

    tp->rcv_adv = export_data->rcv_adv;
    tp->snd_max = export_data->snd_max;

    tp->snd_cwnd = export_data->snd_cwnd;
    tp->snd_ssthresh = export_data->snd_ssthresh;


    tp->t_idle = export_data->idle;
    tp->t_rtt = export_data->rtt;
    tp->t_rtseq = export_data->rtseq;
    tp->t_srtt = export_data->srtt;
    tp->t_rttvar = export_data->rttvar;
    tp->t_rttmin = export_data->rttmin;
    tp->max_sndwnd = export_data->max_sndwnd;

    tp->t_oobflags = export_data->oobflags;
    tp->t_iobc = export_data->iobc;
    
    tp->last_ack_sent = export_data->last_ack_sent;

    tcp_template(tp);
}

// returns how many bytes were written to export_data->data
static int __tcp_socket_export_reass_queue(struct tcpcb *tp, int queue_size, 
                                    TcpSocketExportData *export_data, int data_offset)
{
    char *data = export_data->data + data_offset;
    struct tcpiphdr *q;
    ReassQueueExportData *queue_header;
    int i;

    if (!queue_size) {
        export_data->reass_queue_offset = EXPORT_NULL_OFFSET;
        return 0;
    }
    
    export_data->reass_queue_offset = data_offset;
    queue_header = (ReassQueueExportData *)data;
    queue_header->num_packets = queue_size;

    data = (char*)(queue_header + 1) + (sizeof(int32_t)*queue_size);

    for (i =0, q = tcpfrag_list_first(tp); !tcpfrag_list_end(q, tp); q = tcpiphdr_next(q), i++) {
        __export_tcpip_pckt(q, (TcpMbufExportData *)data);
        queue_header->packets[i] = data - export_data->data;

        data += (sizeof(TcpMbufExportData) + ((TcpMbufExportData *)data)->size);
    }

    return (data - export_data->data + data_offset);
}

static int __tcp_socket_restore_reass_queue(TcpSocketExportData *export_data, struct tcpcb *tp)
{
    ReassQueueExportData *queue_header;
    int i;
    if (export_data->reass_queue_offset == EXPORT_NULL_OFFSET) {
        return TRUE;
    }

    queue_header = (ReassQueueExportData *)(export_data->data + export_data->reass_queue_offset);
    for (i = 0; i < queue_header->num_packets; i++) {
        struct tcpiphdr *ti = __restore_tcpip_pckt((TcpMbufExportData *) (
            export_data->data + queue_header->packets[i]));

        if (!ti) {
            fprintf(stderr, "failed: restoring tcpip packet\n");
            goto error;
        }
        insque(tcpiphdr2qlink(ti), tcpiphdr2qlink(tcpfrag_list_last(tp)));
    }
    
    return TRUE;
error:
    while(!tcpfrag_list_empty(tp)) {
        struct tcpiphdr *ti = tcpfrag_list_first(tp);     
        remque(tcpiphdr2qlink(ti));
        m_free(ti->ti_mbuf);
    }

    return FALSE;
}

uint64_t tcp_socket_export(struct socket *so, void **export_socket)
{
    uint64_t total_size = sizeof(TcpSocketExportData);
    struct tcpcb *tp;
    struct tcpiphdr *q;
    int reass_queue_size = 0;
    TcpSocketExportData *ret;
    int data_offset = 0;

    if ((so->so_state & SS_ISFCONNECTING) && so->so_ti) {
        total_size += sizeof(TcpMbufExportData);
        total_size += __get_tcpip_pckt_size(so->so_ti);
    }

    if (so->so_rcv.sb_datalen) {
        total_size += sizeof(SbufExportData);
        total_size += so->so_rcv.sb_cc;
    }

    if (so->so_snd.sb_datalen) {
        total_size += sizeof(SbufExportData);
        total_size += so->so_snd.sb_cc;
    }

    tp = sototcpcb(so);

    for (q = tcpfrag_list_first(tp); !tcpfrag_list_end(q, tp);
        q = tcpiphdr_next(q)) {
        reass_queue_size++;
        total_size += sizeof(TcpMbufExportData);
        total_size += __get_tcpip_pckt_size(q);
    }

    if (reass_queue_size) {
        total_size += sizeof(ReassQueueExportData);
        total_size += reass_queue_size*sizeof(int32_t);
    }

    ret = (TcpSocketExportData *)malloc(total_size);
    
    data_offset += __tcp_socket_export_socket_data(so, ret, data_offset);
    __tcp_socket_export_tcpcb_data(tp, &ret->tcpcb);
    data_offset += __tcp_socket_export_reass_queue(tp, reass_queue_size, ret, data_offset);
    *export_socket = ret;
    return total_size;
}

struct socket *tcp_socket_restore(void *export_so, UserSocket *usr_so)
{
    TcpSocketExportData *export_data = (TcpSocketExportData *)export_so;
    struct socket *so = __tcp_socket_restore_socket_data(export_data);

    if (!so) {
        return NULL;
    }

    __tcp_socket_restore_tcpcb_data(&export_data->tcpcb, sototcpcb(so));
    
    if (!__tcp_socket_restore_reass_queue(export_data, sototcpcb(so))) {
        // usr_so is still null, so tcp_close will only free resources
        tcp_close(sototcpcb(so));
        return NULL;
    }
    so->usr_so = usr_so;
    return so;
}
