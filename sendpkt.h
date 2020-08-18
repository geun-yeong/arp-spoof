#ifndef SENDPKT_H
#define SENDPKT_H

#include <pcap.h>
#include <libnet.h>

struct arp_body {
    uint8_t snd_mac[6];
    uint8_t snd_ip[4];
    uint8_t tgt_mac[6];
    uint8_t tgt_ip[4];
};

int send_arp(pcap_t *handle, uint8_t *local_mac, uint32_t local_ip, uint8_t *remote_mac, uint32_t remote_ip, uint16_t opcode);

#endif // SENDPKT_H
