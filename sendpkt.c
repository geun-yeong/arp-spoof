#include <pcap.h>
#include <libnet.h>

#include "sendpkt.h"

int send_arp(pcap_t *handle, uint8_t *local_mac, uint32_t local_ip, uint8_t *remote_mac, uint32_t remote_ip, uint16_t opcode)
{
    // frame data buffer
    uint8_t snd_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + sizeof(struct arp_body)];
    int payload_len = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr) + sizeof(struct arp_body);

    // set ethernet header
    struct libnet_ethernet_hdr *snd_eth_hdr = (struct libnet_ethernet_hdr *)(&snd_frame[0]);
    memcpy(snd_eth_hdr->ether_shost, local_mac, 6);
    memcpy(snd_eth_hdr->ether_dhost, remote_mac, 6);
    snd_eth_hdr->ether_type = htons(0x0806);

    // set arp header
    struct libnet_arp_hdr *snd_arp_hdr = (struct libnet_arp_hdr *)(&snd_frame[sizeof(struct libnet_ethernet_hdr)]);
    snd_arp_hdr->ar_hrd = htons(0x0001);
    snd_arp_hdr->ar_pro = htons(0x0800);
    snd_arp_hdr->ar_hln = 6;
    snd_arp_hdr->ar_op = htons((uint16_t)opcode);
    snd_arp_hdr->ar_pln = 4;

    // set arp body(local mac, local ip, remote mac, remote ip)
    struct arp_body *snd_arp_payload = (struct arp_body *)(&snd_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)]);
    memcpy(snd_arp_payload->smac, local_mac, 6);
    *((uint32_t *)&snd_arp_payload->sip) = local_ip;
    memcpy(snd_arp_payload->dmac, remote_mac, 6);
    *((uint32_t *)&snd_arp_payload->dip) = remote_ip;

    // send
    return pcap_sendpacket(handle, snd_frame, payload_len);
}
