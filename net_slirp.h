#ifndef _H_NET_SLIRP
#define _H_NET_SLIRP

#include <stdint.h>
typedef void UserSocket;
typedef void SlirpSocket;
typedef void UserTimer;
typedef void (*timer_proc_t)(void *opaque);

// TODO: only tcp/ip supported
typedef struct SlirpUsrNetworkInterface SlirpUsrNetworkInterface;
struct SlirpUsrNetworkInterface {
    int (*slirp_can_output)(SlirpUsrNetworkInterface *usr_interface);
    void (*slirp_output)(SlirpUsrNetworkInterface *usr_interface, const uint8_t *pkt, int pkt_len);
    int (*connect)(SlirpUsrNetworkInterface *usr_interface, 
        struct in_addr src_addr, uint16_t src_port,
        struct in_addr dst_addr, uint16_t dst_port,
        SlirpSocket *slirp_s, UserSocket **o_usr_s); 
    int (*send)(SlirpUsrNetworkInterface *usr_interface, UserSocket *opaque, 
        uint8_t *buf, size_t len, uint8_t urgent);
    int (*recv)(SlirpUsrNetworkInterface *usr_interface, UserSocket *opaque, 
        uint8_t *buf, size_t len);
    void (*shutdown_send)(SlirpUsrNetworkInterface *usr_interface, UserSocket *opaque);
    void (*shutdown_recv)(SlirpUsrNetworkInterface *usr_interface, UserSocket *opaque);
    void (*close)(SlirpUsrNetworkInterface *usr_interface, UserSocket *opaque);

    UserTimer *(*create_timer)(SlirpUsrNetworkInterface *usr_interface, timer_proc_t proc, 
        void *opaque);
    void       (*arm_timer)(SlirpUsrNetworkInterface *usr_interface, UserTimer *timer, uint32_t ms);
};

void net_slirp_init(struct in_addr special_ip, int restricted, 
                    SlirpUsrNetworkInterface *net_interface);
void net_slirp_set_net_interface(SlirpUsrNetworkInterface *net_interface);
void net_slirp_input(const uint8_t *pkt, int pkt_len);

// TODO: maybe we will need to change the allocation/deallocation to be for specific
// ips (because of problems when client/server restart or client changes network, and
// services were already installed). Maybe the netwrok mask should be extended too.
int net_slirp_allocate_virtual_ip(struct in_addr *addr); 
void net_slirp_clear_virtual_ips(void);

void net_slirp_socket_connected_notify(SlirpSocket *sckt);
void net_slirp_socket_connect_failed_notify(SlirpSocket *sckt);
void net_slirp_socket_can_send_notify(SlirpSocket *sckt); 
void net_slirp_socket_can_receive_notify(SlirpSocket *sckt); 
void net_slirp_socket_abort(SlirpSocket *sckt);

/*
    When exporting slirp, the following steps should be performed in the same order:
    (1) net_slirp_freeze (2) net_slirp_state_export (3) for each tcp socket: net_slirp_tcp_socket_export
    When restoring slirp: (1) net_slirp_state_restore (2) net_slirp_tcp_socket_restore (3) net_slirp_unfreeze
*/

uint64_t net_slirp_state_export(void **export_state);
void net_slirp_state_restore(void *export_state); 

uint64_t net_slirp_tcp_socket_export(SlirpSocket *sckt, void **export_socket);
SlirpSocket *net_slirp_tcp_socket_restore(void *export_socket, UserSocket *usr_socket);

void net_slirp_freeze(void);   // deactivate timers
void net_slirp_unfreeze(void); // restore timers

#if 0

int slirp_redir(int is_udp, int host_port,
                struct in_addr guest_addr, int guest_port);
int slirp_add_exec(int do_pty, const void *args, int addr_low_byte,
                   int guest_port);

void slirp_stats(void);

#endif 


#endif
