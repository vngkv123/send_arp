#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>     // libpcap header
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include "packet_struct.h"

#define 	ETHERTYPE_ARP 	0x0806
#define		ARP_RQUEST		0x1
#define		ARP_REPLY		0x2 


#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

char *dev;

unsigned char mac_address[6];
static unsigned char dhr[6];
const char tip[] = "255.255.255.255";

void find_my_mac(void)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }


    if (success){
		memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	}
	else{
	   	std::cout << "\x1B[36m[-] can't find mac address\x1B[37m" << std::endl;
		exit(0);
	}
}

/*
void arp_request()
{
    unsigned char packet[1514];

	std::cout << "[-] ARP_Request(BroadCast)... then get target's MAC address!" << std::endl;
    struct ether_header* eth_h = (struct ether_header *)packet;
    memcpy(eth_h->ether_dhost, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth_h->ether_shost, my_MACaddr, 6);
    eth_h->type = ntohs(ETHERTYPE_ARP);

    Arp_H* arp_h = (Arp_H *)(packet+sizeof(Ethernet_H));
    arp_h->h_type = htons(1);
    arp_h->p_type = htons(ETHERTYPE_IP);
    arp_h->h_len = 6;
    arp_h->p_len = 4;
    arp_h->oper = ntohs(ARP_REQUEST);
    memcpy(arp_h->sender_MAC, my_MACaddr, 6);
    *(uint32_t *)arp_h->sender_IP = this->my_IPaddr;
    memcpy(arp_h->target_MAC, "\x00\x00\x00\x00\x00\x00", 6);
    *(uint32_t *)arp_h->target_IP = inet_addr(this->sender_IP);

    pcap_sendpacket(this->handle, packet, sizeof(Ethernet_H)+sizeof(Arp_H));
    cout << "[+] ARP_Request is done." << endl;
}
*/

void arp_capture(void)
{
    struct pcap_pkthdr *header; /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    int res;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	std::cout << "[-] Capture ARP_REPLY..." << std::endl;
    /* Grab a packet */
    while(1){
        res = pcap_next_ex(handle, &header, &packet);
        if(res == 1){
            struct ether_header* eth_h = (struct ether_header *)packet;
            if(ntohs(eth_h->ether_type) == ETHERTYPE_ARP){
                struct arp_hdr* arp_h = (struct arp_hdr *)(packet + sizeof(struct ether_header));
                if ((ntohs(arp_h->ar_op) == ARP_REPLY) && (*(uint32_t *)arp_h->ar_sip == inet_addr(tip))){
					std::cout << "\x1B[36m[-] Find target_IP's MAC addr : \x1B[37m";
                    for(int i = 0; i < 6; i++)
                        printf("%02X",(arp_h->ar_sha[i]));
					std::cout << std::endl;
                    memcpy(dhr, arp_h->ar_sha, 6);
                    break;
                }
            }
            else{
                continue;
            }
        }
    }
}

int main(int argc, char *argv[])
{

	if( argc < 4 )
	{
		fprintf(stderr, "\x1B[31m[-] Wrong Usage : %s [en0] [src] [dst]\x1B[37m\n", argv[0]);
	}

	dev = argv[1];
	find_my_mac();
	check_interface(dev);
	check_ipaddr(argv[2], argv[3]);
	arp_capture();

	return 0;
}
