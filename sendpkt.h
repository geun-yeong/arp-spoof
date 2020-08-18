#ifndef SENDPKT_H
#define SENDPKT_H

#include <pcap.h>
#include <libnet.h>

struct arp_body {
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t dmac[6];
    uint8_t dip[4];
};

int send_arp(pcap_t *handle, uint8_t *local_mac, uint32_t local_ip, uint8_t *remote_mac, uint32_t remote_ip, uint16_t opcode);

#endif // SENDPKT_H
