#include <pcap.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <libnet.h>

#include "sendpkt.h"
#include "getaddr.h"



/*
 * get mac address configured in interface
 */
int get_mac_addr_on_dev(char *interface, uint8_t *mac_addr)
{
    int success = 0;
    struct ifreq ether_info = { 0 };

    int sck = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strncpy(ether_info.ifr_name, interface, IF_NAMESIZE-1);

    if( ! ioctl(sck, SIOCGIFHWADDR, &ether_info) ) {
        memcpy(mac_addr, ether_info.ifr_addr.sa_data, 6);
        success = 1;
    }

    close(sck);

    return success;
}


/*
 * get ip address configured in interface
 */
int get_ipv4_addr_on_dev(char *interface, uint32_t *ip_addr)
{
    int success = 0;
    struct ifreq ip_info = { 0 };

    int sck = socket(AF_INET, SOCK_DGRAM, 0);
    ip_info.ifr_addr.sa_family = AF_INET;
    strncpy(ip_info.ifr_name, interface, IF_NAMESIZE);

    if( ! ioctl(sck, SIOCGIFADDR, &ip_info) ) {
        *ip_addr = ((struct sockaddr_in *)&ip_info.ifr_addr)->sin_addr.s_addr;
        success = 1;
    }

    close(sck);

    return success;
}

/*
 * get mac address of remote host
 */
int find_remote_mac_by_arp(pcap_t *if_handle, uint8_t *local_mac, uint32_t local_ip, uint32_t remote_ip, /* out */uint8_t *remote_mac)
{
    int success = 0;

    send_arp(if_handle, local_mac, local_ip, (uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF", remote_ip, ARPOP_REQUEST);

    while ( 1 ) {
        struct pcap_pkthdr *rcv_header;
        const u_char *rcv_frame;

        int result_capturing = pcap_next_ex(if_handle, &rcv_header, &rcv_frame);

        // error occurred.
        if( result_capturing < 0 )
        {
            fprintf(stderr, "Error occurred at pcap_next_ex\n");
            fprintf(stderr, "Error Message: %s\n", pcap_geterr(if_handle));
            break;
        }

        // timeout.
        else if( result_capturing == 0 )
        {
            continue;
        }

        // success to capture a packet without problems.
        else
        {
            if( ! IS_ARP(&rcv_frame[0]) ) continue; // check that upper protocol whether arp or not

            struct libnet_arp_hdr *rcv_arp_hdr = (struct libnet_arp_hdr *)(&rcv_frame[sizeof(struct libnet_ethernet_hdr)]);
            struct arp_body *rcv_payload = (struct arp_body *)(&rcv_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)]);
            uint32_t sip = (*((uint32_t *)rcv_payload->snd_ip));

            if( ntohs(rcv_arp_hdr->ar_op) == ARPOP_REPLY && sip == remote_ip) {
                memcpy(remote_mac, rcv_payload->snd_mac, 6);
                success = 1;
                break;
            }
        }
    }

    return success;
}
