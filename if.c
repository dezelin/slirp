/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

#include "slirp_common.h"
#include "if.h"
#include "bootp.h"

int     if_queued = 0;                  /* Number of packets queued so far */

struct  mbuf if_fastq;                  /* fast queue (for interactive data) */
struct  mbuf if_batchq;                 /* queue for non-interactive data */
struct	mbuf *next_m;			/* Pointer to next mbuf to output */

#define ifs_init(ifm) ((ifm)->ifs_next = (ifm)->ifs_prev = (ifm))

static void
ifs_insque(struct mbuf *ifm, struct mbuf *ifmhead)
{
	ifm->ifs_next = ifmhead->ifs_next;
	ifmhead->ifs_next = ifm;
	ifm->ifs_prev = ifmhead;
	ifm->ifs_next->ifs_prev = ifm;
}

static void
ifs_remque(struct mbuf *ifm)
{
	ifm->ifs_prev->ifs_next = ifm->ifs_next;
	ifm->ifs_next->ifs_prev = ifm->ifs_prev;
}

void
if_init()
{
	if_fastq.ifq_next = if_fastq.ifq_prev = &if_fastq;
	if_batchq.ifq_next = if_batchq.ifq_prev = &if_batchq;
        //	sl_compress_init(&comp_s);
	next_m = &if_batchq;
}


#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		    /* ARP reply			*/

struct ethhdr
{
	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
	unsigned short	h_proto;		/* packet type ID field	*/
};

struct arphdr
{
	unsigned short	ar_hrd;		/* format of hardware address	*/
	unsigned short	ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	unsigned short	ar_op;		/* ARP opcode (command)		*/

	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[ETH_ALEN];	/* sender hardware address	*/
	unsigned char		ar_sip[4];		/* sender IP address		*/
	unsigned char		ar_tha[ETH_ALEN];	/* target hardware address	*/
	unsigned char		ar_tip[4];		/* target IP address		*/
};

void arp_input(const uint8_t *pkt, int pkt_len)
{
    struct ethhdr *eh = (struct ethhdr *)pkt;
    struct arphdr *ah = (struct arphdr *)(pkt + ETH_HLEN);
    uint8_t arp_reply[ETH_HLEN + sizeof(struct arphdr)];
    struct ethhdr *reh = (struct ethhdr *)arp_reply;
    struct arphdr *rah = (struct arphdr *)(arp_reply + ETH_HLEN);
    int ar_op;
    //struct ex_list *ex_ptr;

    ar_op = ntohs(ah->ar_op);
    switch(ar_op) {
    case ARPOP_REQUEST:
        if (is_virtual_ip_allocated((struct in_addr *)ah->ar_tip)) {
            goto arp_ok;
        } else {
             return;
        }

#if 0
        if (!memcmp(ah->ar_tip, &special_addr, 3)) {
            if (ah->ar_tip[3] == CTL_DNS || ah->ar_tip[3] == CTL_ALIAS)
                goto arp_ok;
            for (ex_ptr = exec_list; ex_ptr; ex_ptr = ex_ptr->ex_next) {
                if (ex_ptr->ex_addr == ah->ar_tip[3])
                    goto arp_ok;
            }
#endif           
        arp_ok:
            /* XXX: make an ARP request to have the client address */
            memcpy(client_ethaddr, eh->h_source, ETH_ALEN);

            /* ARP request for alias/dns mac address */
            memcpy(reh->h_dest, pkt + ETH_ALEN, ETH_ALEN);
            memcpy(reh->h_source, special_ethaddr, ETH_ALEN - 1);
            reh->h_source[5] = ah->ar_tip[3];
            reh->h_proto = htons(ETH_P_ARP);

            rah->ar_hrd = htons(1);
            rah->ar_pro = htons(ETH_P_IP);
            rah->ar_hln = ETH_ALEN;
            rah->ar_pln = 4;
            rah->ar_op = htons(ARPOP_REPLY);
            memcpy(rah->ar_sha, reh->h_source, ETH_ALEN);
            memcpy(rah->ar_sip, ah->ar_tip, 4);
            memcpy(rah->ar_tha, ah->ar_sha, ETH_ALEN);
            memcpy(rah->ar_tip, ah->ar_sip, 4);
            slirp_net_interface->slirp_output(slirp_net_interface, arp_reply, sizeof(arp_reply));
        break;
    case ARPOP_REPLY:   
        /* reply to request of client mac address ? */
        if (!memcmp(client_ethaddr, zero_ethaddr, ETH_ALEN) &&
            !memcmp(ah->ar_sip, &client_ipaddr.s_addr, 4)) {
            memcpy(client_ethaddr, ah->ar_sha, ETH_ALEN);
        }
        break;
    default:
        break;
    }
}

/* output the IP packet to the ethernet device */
static void if_encap(const uint8_t *ip_data, int ip_data_len)
{
    uint8_t buf[1600];
    struct ethhdr *eh = (struct ethhdr *)buf;

    if (ip_data_len + ETH_HLEN > sizeof(buf))
        return;
    
    if (!memcmp(client_ethaddr, zero_ethaddr, ETH_ALEN)) {
        uint8_t arp_req[ETH_HLEN + sizeof(struct arphdr)];
        struct ethhdr *reh = (struct ethhdr *)arp_req;
        struct arphdr *rah = (struct arphdr *)(arp_req + ETH_HLEN);
        const struct ip *iph = (const struct ip *)ip_data;

        /* If the client addr is not known, there is no point in
           sending the packet to it. Normally the sender should have
           done an ARP request to get its MAC address. Here we do it
           in place of sending the packet and we hope that the sender
           will retry sending its packet. */
        memset(reh->h_dest, 0xff, ETH_ALEN);
        memcpy(reh->h_source, special_ethaddr, ETH_ALEN - 1);
        reh->h_source[5] = CTL_ALIAS;
        reh->h_proto = htons(ETH_P_ARP);
        rah->ar_hrd = htons(1);
        rah->ar_pro = htons(ETH_P_IP);
        rah->ar_hln = ETH_ALEN;
        rah->ar_pln = 4;
        rah->ar_op = htons(ARPOP_REQUEST);
        /* source hw addr */
        memcpy(rah->ar_sha, special_ethaddr, ETH_ALEN - 1);
        rah->ar_sha[5] = CTL_ALIAS;
        /* source IP */
        memcpy(rah->ar_sip, &alias_addr, 4);
        /* target hw addr (none) */
        memset(rah->ar_tha, 0, ETH_ALEN);
        /* target IP */
        memcpy(rah->ar_tip, &iph->ip_dst, 4);
        client_ipaddr = iph->ip_dst;
        slirp_net_interface->slirp_output(slirp_net_interface, arp_req, sizeof(arp_req));
    } else {
        memcpy(eh->h_dest, client_ethaddr, ETH_ALEN);
        memcpy(eh->h_source, special_ethaddr, ETH_ALEN - 1);
        /* XXX: not correct */
        eh->h_source[5] = CTL_ALIAS;
        eh->h_proto = htons(ETH_P_IP);
        memcpy(buf + sizeof(struct ethhdr), ip_data, ip_data_len);
        slirp_net_interface->slirp_output(slirp_net_interface, buf, ip_data_len + ETH_HLEN);
    }
}


/*
 * if_output: Queue packet into an output queue.
 * There are 2 output queue's, if_fastq and if_batchq.
 * Each output queue is a doubly linked list of double linked lists
 * of mbufs, each list belonging to one "session" (socket).  This
 * way, we can output packets fairly by sending one packet from each
 * session, instead of all the packets from one session, then all packets
 * from the next session, etc.  Packets on the if_fastq get absolute
 * priority, but if one session hogs the link, it gets "downgraded"
 * to the batchq until it runs out of packets, then it'll return
 * to the fastq (eg. if the user does an ls -alR in a telnet session,
 * it'll temporarily get downgraded to the batchq)
 */
void
if_output(so, ifm)
	struct socket *so;
	struct mbuf *ifm;
{
	struct mbuf *ifq;
	int on_fastq = 1;

	DEBUG_CALL("if_output");
	DEBUG_ARG("so = %lx", (long)so);
	DEBUG_ARG("ifm = %lx", (long)ifm);

	/*
	 * First remove the mbuf from m_usedlist,
	 * since we're gonna use m_next and m_prev ourselves
	 * XXX Shouldn't need this, gotta change dtom() etc.
	 */
	if (ifm->m_flags & M_USEDLIST) {
		remque(ifm);
		ifm->m_flags &= ~M_USEDLIST;
	}

	/*
	 * See if there's already a batchq list for this session.
	 * This can include an interactive session, which should go on fastq,
	 * but gets too greedy... hence it'll be downgraded from fastq to batchq.
	 * We mustn't put this packet back on the fastq (or we'll send it out of order)
	 * XXX add cache here?
	 */
	for (ifq = if_batchq.ifq_prev; ifq != &if_batchq; ifq = ifq->ifq_prev) {
		if (so == ifq->ifq_so) {
			/* A match! */
			ifm->ifq_so = so;
			ifs_insque(ifm, ifq->ifs_prev);
			goto diddit;
		}
	}

	/* No match, check which queue to put it on */
	if (so && (so->so_iptos & IPTOS_LOWDELAY)) {
		ifq = if_fastq.ifq_prev;
		on_fastq = 1;
		/*
		 * Check if this packet is a part of the last
		 * packet's session
		 */
		if (ifq->ifq_so == so) {
			ifm->ifq_so = so;
			ifs_insque(ifm, ifq->ifs_prev);
			goto diddit;
		}
	} else
		ifq = if_batchq.ifq_prev;

	/* Create a new doubly linked list for this session */
	ifm->ifq_so = so;
	ifs_init(ifm);
	insque(ifm, ifq);

diddit:
	++if_queued;

	if (so) {
		/* Update *_queued */
		so->so_queued++;
		so->so_nqueued++;
		/*
		 * Check if the interactive session should be downgraded to
		 * the batchq.  A session is downgraded if it has queued 6
		 * packets without pausing, and at least 3 of those packets
		 * have been sent over the link
		 * (XXX These are arbitrary numbers, probably not optimal..)
		 */
		if (on_fastq && ((so->so_nqueued >= 6) &&
				 (so->so_nqueued - so->so_queued) >= 3)) {

			/* Remove from current queue... */
			remque(ifm->ifs_next);

			/* ...And insert in the new.  That'll teach ya! */
			insque(ifm->ifs_next, &if_batchq);
		}
	}

#ifndef FULL_BOLT
	/*
	 * This prevents us from malloc()ing too many mbufs
	 */
	if (link_up) {
		/* if_start will check towrite */
		if_start();
	}
#endif
}

/*
 * Send a packet
 * We choose a packet based on it's position in the output queues;
 * If there are packets on the fastq, they are sent FIFO, before
 * everything else.  Otherwise we choose the first packet from the
 * batchq and send it.  the next packet chosen will be from the session
 * after this one, then the session after that one, and so on..  So,
 * for example, if there are 3 ftp session's fighting for bandwidth,
 * one packet will be sent from the first session, then one packet
 * from the second session, then one packet from the third, then back
 * to the first, etc. etc.
 */
void
if_start(void)
{
	struct mbuf *ifm, *ifqt;

	DEBUG_CALL("if_start");

	if (if_queued == 0)
	   return; /* Nothing to do */

 again:
        /* check if we can really output */
    if (!slirp_net_interface->slirp_can_output(slirp_net_interface))
            return;

	/*
	 * See which queue to get next packet from
	 * If there's something in the fastq, select it immediately
	 */
	if (if_fastq.ifq_next != &if_fastq) {
		ifm = if_fastq.ifq_next;
	} else {
		/* Nothing on fastq, see if next_m is valid */
		if (next_m != &if_batchq)
		   ifm = next_m;
		else
		   ifm = if_batchq.ifq_next;

		/* Set which packet to send on next iteration */
		next_m = ifm->ifq_next;
	}
	/* Remove it from the queue */
	ifqt = ifm->ifq_prev;
	remque(ifm);
	--if_queued;

	/* If there are more packets for this session, re-queue them */
	if (ifm->ifs_next != /* ifm->ifs_prev != */ ifm) {
		insque(ifm->ifs_next, ifqt);
		ifs_remque(ifm);
	}

	/* Update so_queued */
	if (ifm->ifq_so) {
		if (--ifm->ifq_so->so_queued == 0)
		   /* If there's no more queued, reset nqueued */
		   ifm->ifq_so->so_nqueued = 0;
	}

	/* Encapsulate the packet for sending */
        if_encap((uint8_t *)ifm->m_data, ifm->m_len);

        m_free(ifm);

	if (if_queued)
	   goto again;
}
