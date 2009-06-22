/*
 * QEMU BOOTP/DHCP server
 *
 * Copyright (c) 2004 Fabrice Bellard
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
#include "bootp.h"
#include "slirp_common.h"
#include "udp.h"
#include "if.h"

/* XXX: only DHCP is supported */

#define NB_ADDR 16 

#define START_ADDR 15
#define START_VIRTAUL_ADDR (NB_ADDR + START_ADDR)

#define LEASE_TIME (24 * 3600)

typedef struct __attribute__((packed)) {
    uint8_t macaddr[6];
} BOOTPClient;

static BOOTPClient bootp_clients[NB_ADDR];
static int num_bootp_clients = 0;
static int num_virtual_ips = 0;

const char *bootp_filename;

static const uint8_t rfc1533_cookie[] = { RFC1533_COOKIE };

#ifdef DEBUG
#define dprintf(fmt, args...) \
if (slirp_debug & DBG_CALL) { fprintf(dfd, fmt, ## args); fflush(dfd); }
#else
#define dprintf(fmt, args...)
#endif

static BOOTPClient *get_new_addr(struct in_addr *paddr)
{
    BOOTPClient *bc;

    if (num_bootp_clients == NB_ADDR) {
        return NULL;
    }

    bc = &bootp_clients[num_bootp_clients];
    paddr->s_addr = htonl(ntohl(special_addr.s_addr) | (num_bootp_clients + START_ADDR));
    num_bootp_clients++;
    return bc;
}

static BOOTPClient *find_addr(struct in_addr *paddr, const uint8_t *macaddr)
{
    BOOTPClient *bc;
    int i;

    for(i = 0; i < num_bootp_clients; i++) {
        if (!memcmp(macaddr, bootp_clients[i].macaddr, 6))
            goto found;
    }
    return NULL;
 found:
    bc = &bootp_clients[i];
    paddr->s_addr = htonl(ntohl(special_addr.s_addr) | (i + START_ADDR));
    return bc;
}

int alloc_virtual_ip(struct in_addr *out_addr)
{
    if ((num_virtual_ips + START_VIRTAUL_ADDR) > 0xff)
        return FALSE;
    out_addr->s_addr = htonl(ntohl(special_addr.s_addr) | (num_virtual_ips + START_VIRTAUL_ADDR));
    num_virtual_ips++;
    return TRUE;
}

void clear_virtual_ips()
{
    num_virtual_ips = 0;
}

int is_virtual_ip_allocated(struct in_addr *addr)
{
    if ((addr->s_addr&htonl(0xffffff00)) == special_addr.s_addr) {
        int lastbyte=(ntohl(addr->s_addr)) & 0xff;
        return (((lastbyte >= START_VIRTAUL_ADDR) && 
            (lastbyte < num_virtual_ips + START_VIRTAUL_ADDR)) ||(lastbyte == CTL_ALIAS) );
    }
    return FALSE;
}


static void dhcp_decode(const uint8_t *buf, int size,
                        int *pmsg_type)
{
    const uint8_t *p, *p_end;
    int len, tag;

    *pmsg_type = 0;

    p = buf;
    p_end = buf + size;
    if (size < 5)
        return;
    if (memcmp(p, rfc1533_cookie, 4) != 0)
        return;
    p += 4;
    while (p < p_end) {
        tag = p[0];
        if (tag == RFC1533_PAD) {
            p++;
        } else if (tag == RFC1533_END) {
            break;
        } else {
            p++;
            if (p >= p_end)
                break;
            len = *p++;
            dprintf("dhcp: tag=0x%02x len=%d\n", tag, len);

            switch(tag) {
            case RFC2132_MSG_TYPE:
                if (len >= 1)
                    *pmsg_type = p[0];
                break;
            default:
                break;
            }
            p += len;
        }
    }
}

static void bootp_reply(struct bootp_t *bp)
{
    BOOTPClient *bc;
    struct mbuf *m;
    struct bootp_t *rbp;
    struct sockaddr_in saddr, daddr;
#if 0
    struct in_addr dns_addr;
#endif
    int reply_nack = 0;
    int dhcp_msg_type, val;
    uint8_t *q;

    /* extract exact DHCP msg type */
    dhcp_decode(bp->bp_vend, DHCP_OPT_LEN, &dhcp_msg_type);
    dprintf("bootp packet op=%d msgtype=%d\n", bp->bp_op, dhcp_msg_type);

    if (dhcp_msg_type == 0)
        dhcp_msg_type = DHCPREQUEST; /* Force reply for old BOOTP clients */

    if (dhcp_msg_type != DHCPDISCOVER &&
        dhcp_msg_type != DHCPREQUEST)
        return;
    /* XXX: this is a hack to get the client mac address */
    memcpy(client_ethaddr, bp->bp_hwaddr, 6);

    if ((m = m_get()) == NULL)
        return;
    m->m_data += IF_MAXLINKHDR;
    rbp = (struct bootp_t *)m->m_data;
    m->m_data += sizeof(struct udpiphdr);
    memset(rbp, 0, sizeof(struct bootp_t));

    if (dhcp_msg_type == DHCPDISCOVER) {
        bc = find_addr(&daddr.sin_addr, bp->bp_hwaddr);
        if (!bc) {
            bc = get_new_addr(&daddr.sin_addr);
        } 

        if (!bc) {
            dprintf("no address left\n");
            return;
        }

        memcpy(bc->macaddr, client_ethaddr, 6);
    } else {
        bc = find_addr(&daddr.sin_addr, bp->bp_hwaddr);
        if (!bc) {
            // The requested address might no be in our network. We return nack.
            // TODO: make this nicer by checking if the requested address is valid and
            // accordingly allocating it or return nack.
            reply_nack = 1;
            inet_aton("255.255.255.255", &daddr.sin_addr);
        }
    }

 

    if (bootp_filename)
        snprintf((char *)rbp->bp_file, sizeof(rbp->bp_file), "%s",
                 bootp_filename);

    dprintf("offered addr=%08x\n", ntohl(daddr.sin_addr.s_addr));

    saddr.sin_addr.s_addr = htonl(ntohl(special_addr.s_addr) | CTL_ALIAS);
    saddr.sin_port = htons(BOOTP_SERVER);

    daddr.sin_port = htons(BOOTP_CLIENT);

    rbp->bp_op = BOOTP_REPLY;
    rbp->bp_xid = bp->bp_xid;
    rbp->bp_htype = 1;
    rbp->bp_hlen = 6;
    memcpy(rbp->bp_hwaddr, bp->bp_hwaddr, 6);

    if (!reply_nack) {
        rbp->bp_yiaddr = daddr.sin_addr; /* Client IP address */
        rbp->bp_siaddr = saddr.sin_addr; /* Server IP address */
    } 
  
    q = rbp->bp_vend;
    memcpy(q, rfc1533_cookie, 4);
    q += 4;

    if (dhcp_msg_type == DHCPDISCOVER) {
        *q++ = RFC2132_MSG_TYPE;
        *q++ = 1;
        *q++ = DHCPOFFER;
    } else if (dhcp_msg_type == DHCPREQUEST) {
        *q++ = RFC2132_MSG_TYPE;
        *q++ = 1;

        if (!reply_nack) {
            *q++ = DHCPACK;
        } else {
            *q++ = DHCPNACK;
        }
    }

    if (dhcp_msg_type == DHCPDISCOVER ||
        dhcp_msg_type == DHCPREQUEST) {
        *q++ = RFC2132_SRV_ID;
        *q++ = 4;
        memcpy(q, &saddr.sin_addr, 4);
        q += 4;

        if (!reply_nack) {
            *q++ = RFC1533_NETMASK;
            *q++ = 4;
            *q++ = 0xff;
            *q++ = 0xff;
            *q++ = 0xff;
            *q++ = 0x00;
     
            if (!slirp_restricted) {
                *q++ = RFC1533_GATEWAY;
                *q++ = 4;
                memcpy(q, &saddr.sin_addr, 4);
                q += 4;

                *q++ = RFC1533_DNS;
                *q++ = 4;
                dns_addr.s_addr = htonl(ntohl(special_addr.s_addr) | CTL_DNS);
                memcpy(q, &dns_addr, 4);
                q += 4;
              }

            *q++ = RFC2132_LEASE_TIME;
            *q++ = 4;
            val = htonl(LEASE_TIME);
            memcpy(q, &val, 4);
            q += 4;

            if (*slirp_hostname) {
                val = strlen(slirp_hostname);
                *q++ = RFC1533_HOSTNAME;
                *q++ = val;
                memcpy(q, slirp_hostname, val);
                q += val;
            }   

        }
    }
    *q++ = RFC1533_END;

    m->m_len = sizeof(struct bootp_t) -
        sizeof(struct ip) - sizeof(struct udphdr);
    udp_output2(NULL, m, &saddr, &daddr, IPTOS_LOWDELAY);
}

void bootp_input(struct mbuf *m)
{
    struct bootp_t *bp = mtod(m, struct bootp_t *);
    
    if (bp->bp_op == BOOTP_REQUEST) {
        bootp_reply(bp);
    }
}

typedef struct __attribute__((packed)) BootpExportData {
    uint32_t num_virtual_ips;
    uint32_t num_bootp_clients;
    BOOTPClient  clients[0]; // ptr to the start of the mcadder of the bootp client
} BootpExportData;

uint64_t bootp_export(void **export_data)
{
    int i;
    uint64_t size = sizeof(BootpExportData) + (sizeof(BOOTPClient)*num_bootp_clients);
    BootpExportData *ret_data =  malloc(size);

    ret_data->num_virtual_ips = num_virtual_ips;
    ret_data->num_bootp_clients = num_bootp_clients;

    for (i = 0; i < ret_data->num_bootp_clients ; i++) {
        memcpy(ret_data->clients[i].macaddr, bootp_clients[i].macaddr, 6);
    }

    *export_data = ret_data;
    return size;
}

void bootp_restore(void *export_data)
{
    int i;
    BootpExportData *bootp_data = (BootpExportData *)export_data;

    num_virtual_ips = bootp_data->num_virtual_ips;
    num_bootp_clients = bootp_data->num_bootp_clients;

    for (i = 0; i < num_bootp_clients; i++)
    {
        memcpy(bootp_clients[i].macaddr, bootp_data->clients[i].macaddr, 6);
    }
}
