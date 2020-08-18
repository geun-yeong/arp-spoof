#ifndef GETADDR_H
#define GETADDR_H

#include <pcap.h>
#include <libnet.h>

#define IS_ARP(x) (ntohs(((struct libnet_ethernet_hdr *)(x))->ether_type) == (uint16_t)ETHERTYPE_ARP)
#define IS_IPV4(x) (ntohs(((struct libnet_ethernet_hdr *)(x))->ether_type) == (uint16_t)ETHERTYPE_IP)

int get_mac_addr_on_dev(char *interface, /* out */uint8_t *mac_addr);
int get_ipv4_addr_on_dev(char *interface, /* out */uint32_t *ip_addr);
int find_remote_mac_by_arp(pcap_t *if_handle, uint8_t *local_mac, uint32_t local_ip, uint32_t remote_ip, /* out */uint8_t *remote_mac);

#endif // GETADDR_H
