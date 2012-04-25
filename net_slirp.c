/*
 * libslirp glue
 *
 * Copyright (c) 2004-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "slirp_common.h"
#include "net_slirp.h"
#include "if.h"
#include "ip.h"
#include "mbuf.h"
#include "ctl.h"
#include "socket.h"
#include "tcp.h"
#include "socket.h"
#include "bootp.h"

#define DLL_PUBLIC __attribute__ ((visibility ("default")))
/* host address */
struct in_addr our_addr;
/* host dns address */
struct in_addr dns_addr;
/* host loopback address */
struct in_addr loopback_addr;

/* address for slirp virtual addresses */
struct in_addr special_addr;
/* virtual address alias for host */
struct in_addr alias_addr;
const uint8_t zero_ethaddr[6] = { 0, 0, 0, 0, 0, 0 };
const uint8_t special_ethaddr[6] = {
    0x52, 0x54, 0x00, 0x12, 0x35, 0x00
};

int slirp_restricted;

/* ARP cache for the guest IP addresses (XXX: allow many entries) */
uint8_t client_ethaddr[6]; // bootp_reply sets it or arp...
struct in_addr client_ipaddr;


int link_up = 0;
FILE *lfd;

char slirp_hostname[33];

SlirpUsrNetworkInterface *slirp_net_interface;

UserTimer *fast_timer, *slow_timer;
int fast_timer_armed, slow_timer_armed;

int slirp_freezed = 0;

/*
u_int curtime, last_fasttimo, last_slowtimo;
static void updtime(void)
{
	gettimeofday(&tt, 0);

	curtime = (u_int)tt.tv_sec * (u_int)1000;
	curtime += (u_int)tt.tv_usec / (u_int)1000;

	if ((tt.tv_usec % 1000) >= 500)
	   curtime++;
}*/

static int get_dns_addr(struct in_addr *pdns_addr)
{
    char buff[512];
    char buff2[257];
    FILE *f;
    int found = 0;
    struct in_addr tmp_addr;

    f = fopen("/etc/resolv.conf", "r");
    if (!f)
        return -1;

#ifdef DEBUG
    lprint("IP address of your DNS(s): ");
#endif
    while (fgets(buff, 512, f) != NULL) {
        if (sscanf(buff, "nameserver%*[ \t]%256s", buff2) == 1) {
            if (!inet_aton(buff2, &tmp_addr))
                continue;
            if (tmp_addr.s_addr == loopback_addr.s_addr)
                tmp_addr = our_addr;
            /* If it's the first one, set it to dns_addr */
            if (!found)
                *pdns_addr = tmp_addr;
#ifdef DEBUG
            else
                lprint(", ");
#endif
            if (++found > 3) {
#ifdef DEBUG
                lprint("(more)");
#endif
                break;
            }
#ifdef DEBUG
            else
                lprint("%s", inet_ntoa(tmp_addr));
#endif
        }
    }
    fclose(f);
    if (!found)
        return -1;
    return 0;
}


/*
 * Get our IP address and put it in our_addr
 */
static void getouraddr(void)
{
	char buff[256];
	struct hostent *he = NULL;

	if (gethostname(buff,256) == 0)
            he = gethostbyname(buff);
        if (he)
            our_addr = *(struct in_addr *)he->h_addr;
        if (our_addr.s_addr == 0)
            our_addr.s_addr = loopback_addr.s_addr;
}

static int need_fast_timer(void) 
{
    // the timer will check if realy needed (if there is pending delayed ack)
    return (if_queued || (tcb.so_next != &tcb));
}

static int need_slow_timer(void) 
{
    return ((tcb.so_next != &tcb) || (&ipq.ip_link != ipq.ip_link.next));
}

static void fast_timeout(void *opaque)
{
    if (slirp_freezed) {
        return;
    }

    tcp_fasttimo();

    if (if_queued)
	   if_start();
    if (need_fast_timer()) {
        slirp_net_interface->arm_timer(slirp_net_interface, fast_timer, FAST_TIMEOUT_MS);
    } else {
        fast_timer_armed = 0;
    }
}

static void slow_timeout(void *opaque)
{
    if (slirp_freezed) {
        return;
    }

    ip_slowtimo();
	tcp_slowtimo();
    if (need_slow_timer()) {
        slirp_net_interface->arm_timer(slirp_net_interface, slow_timer, SLOW_TIMEOUT_MS);
    } else {
        slow_timer_armed = 0;
    }
}


void DLL_PUBLIC net_slirp_init(struct in_addr special_ip, int restricted, 
                               SlirpUsrNetworkInterface *net_interface)
{
    //    debug_init("/tmp/slirp.log", DEBUG_DEFAULT);
    link_up = 1;

    if_init();
    ip_init();

    /* Initialise mbufs *after* setting the MTU */
    m_init();

    /* set default addresses */
    inet_aton("127.0.0.1", &loopback_addr);

    if (get_dns_addr(&dns_addr) < 0) {
        dns_addr = loopback_addr;
        fprintf (stderr, "Warning: No DNS servers found\n");
    }

    special_addr.s_addr = special_ip.s_addr;
    alias_addr.s_addr = special_addr.s_addr | htonl(CTL_ALIAS);

    slirp_restricted = restricted;
    slirp_net_interface = net_interface;

    getouraddr();

    fast_timer = net_interface->create_timer(net_interface, fast_timeout, NULL);
    slow_timer = net_interface->create_timer(net_interface, slow_timeout, NULL);
    fast_timer_armed = 0;
    slow_timer_armed = 0;

}

void DLL_PUBLIC net_slirp_set_net_interface(SlirpUsrNetworkInterface *net_interface)
{
    slirp_net_interface = net_interface;
}

void DLL_PUBLIC net_slirp_input(const uint8_t *pkt, int pkt_len)
{
    struct mbuf *m;
    int proto;

    if (pkt_len < ETH_HLEN)
        return;

    proto = ntohs(*(uint16_t *)(pkt + 12));
    switch(proto) {
    case ETH_P_ARP:
        arp_input(pkt, pkt_len);
        break;
    case ETH_P_IP:
        m = m_get();
        if (!m)
            return;
        /* Note: we add to align the IP header */
        if (M_FREEROOM(m) < pkt_len + 2) {
            m_inc(m, pkt_len + 2);
        }
        m->m_len = pkt_len + 2;
        memcpy(m->m_data + 2, pkt, pkt_len);

        m->m_data += 2 + ETH_HLEN;
        m->m_len -= 2 + ETH_HLEN;

        ip_input(m);
        break;
    default:
        printf("SLIRP INPUT : unsupported protocol %x\n", proto);
        break;
    }

    if (!slow_timer_armed && need_slow_timer()) {
        slirp_net_interface->arm_timer(slirp_net_interface, slow_timer, SLOW_TIMEOUT_MS);
    }

    if (!fast_timer_armed && need_fast_timer()) {
        slirp_net_interface->arm_timer(slirp_net_interface, fast_timer, FAST_TIMEOUT_MS);
    }
}



void DLL_PUBLIC net_slirp_socket_connected_notify(SlirpSocket *sckt)
{
    struct socket *so = (struct socket *)sckt;
    so->so_state &= ~SS_ISFCONNECTING;
     
    // when tcp_input is called with null, the connection continues
    tcp_input((struct mbuf *)NULL, sizeof(struct ip), so);
}

void DLL_PUBLIC net_slirp_socket_connect_failed_notify(SlirpSocket *sckt)
{
    struct socket *so = (struct socket *)sckt;
    so->so_state = SS_NOFDREF;
    tcp_input((struct mbuf *)NULL, sizeof(struct ip), so);
}

void DLL_PUBLIC net_slirp_socket_can_send_notify(SlirpSocket *sckt)
{
    struct socket *so = (struct socket *)sckt;
    if (socansend(so)) {
        sowrite(so);
    }
    
}

void DLL_PUBLIC net_slirp_socket_can_receive_notify(SlirpSocket *sckt)
{
    struct socket *so = (struct socket *)sckt;
    // if we can't read cause a buffer is full, we will try again after sodropacked
    if (socanrecv(so)) {
        if (soread(so) > 0) {
            tcp_output(sototcpcb(so));
        }
    }    
}

void DLL_PUBLIC net_slirp_socket_abort(SlirpSocket *sckt)
{
   struct socket *so = (struct socket *)sckt;
   tcp_drop(sototcpcb(so), 0);
}

int DLL_PUBLIC net_slirp_allocate_virtual_ip(struct in_addr *addr)
{
    return alloc_virtual_ip(addr); // bootp
}

void DLL_PUBLIC net_slirp_clear_virtual_ips(void)
{
    clear_virtual_ips();
}


typedef struct __attribute__((packed)) SlirpExportData {
    uint8_t client_ethaddr[6];
    uint8_t client_ipaddr[4];
    uint32_t tcp_iss;
    uint8_t  bootp_data[0];
} SlirpExportData;  

uint64_t DLL_PUBLIC net_slirp_state_export(void **export_state)
{
    void *bootp_data;
    uint64_t bootp_size;
    SlirpExportData *ret_data;
    uint64_t total_size;

    bootp_size = bootp_export(&bootp_data);
    total_size = sizeof(SlirpExportData) + bootp_size;
    ret_data = malloc(total_size);

    memcpy(ret_data->client_ethaddr, client_ethaddr, 6);
    memcpy(ret_data->client_ipaddr, &client_ipaddr.s_addr, 4);
    ret_data->tcp_iss = tcp_iss;
    memcpy(ret_data->bootp_data, bootp_data, bootp_size);
    free(bootp_data);

    *export_state = ret_data;
    return total_size;
}


void DLL_PUBLIC net_slirp_state_restore(void *export_state)
{
    SlirpExportData *slirp_data = (SlirpExportData *)export_state;

    bootp_restore(slirp_data->bootp_data);
    tcp_iss = slirp_data->tcp_iss;
    memcpy(client_ethaddr, slirp_data->client_ethaddr, 6);
    memcpy(&client_ipaddr.s_addr, slirp_data->client_ipaddr, 4);
    slirp_freezed = TRUE;

}

uint64_t DLL_PUBLIC net_slirp_tcp_socket_export(SlirpSocket *sckt, void **export_socket)
{
    return tcp_socket_export((struct socket *)sckt, export_socket);
}

SlirpSocket DLL_PUBLIC *net_slirp_tcp_socket_restore(void *export_socket, UserSocket *usr_socket)
{
    SlirpSocket *ret = tcp_socket_restore(export_socket, usr_socket);


    return ret;
}


void DLL_PUBLIC net_slirp_freeze(void)
{
    slirp_freezed = TRUE;
}


void DLL_PUBLIC net_slirp_unfreeze(void)
{
    slirp_freezed = FALSE;
    if (!slow_timer_armed && need_slow_timer()) {
        slirp_net_interface->arm_timer(slirp_net_interface, slow_timer, SLOW_TIMEOUT_MS);
    }

    if (!fast_timer_armed && need_fast_timer()) {
        slirp_net_interface->arm_timer(slirp_net_interface, fast_timer, FAST_TIMEOUT_MS);
    }
}
