#ifndef SOCKET_REDIRECT_H
#define SOCKET_REDIRECT_H

struct sock_key {
    __u32 sip4;
    __u32 dip4;
    __u32 family;
    __u32 sport;
    __u32 dport;
};

struct connection_info {
    __u32 sip4;
    __u32 dip4;
    __u32 family;
    __u16 sport;
    __u16 dport;
};

#endif // SOCKET_REDIRECT_H
