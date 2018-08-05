#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

typedef unsigned short ushort;
typedef unsigned char uchar;

void check_interface(char *interface);
void check_ipaddr(char source[16], char destination[16]);

struct ether_addr
{
        unsigned char ether_addr_octet[6];
};
 
struct ether_header
{
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        unsigned short ether_type;
} __attribute__((packed));

// ARP header
struct arp_hdr
{
	ushort	ar_hrd;		// Hardware type : ethernet
	ushort	ar_pro;     // Protocol		 : IP(0x0800)
	uchar	ar_hln;     // Hardware size
	uchar	ar_pln;     // Protocal size
	ushort	ar_op;      // Opcode replay : Request(1), Replay(2)
	uchar	ar_sha[6];  // Sender MAC
	uchar	ar_sip[4];  // Sender IP
	uchar	ar_tha[6];  // Target mac
	uchar	ar_tip[4];  // Target IP
} __attribute__((packed));
 
struct ip_header
{
        unsigned char ip_header_len:4;
        unsigned char ip_version:4;
        unsigned char ip_tos;
        unsigned short ip_total_length;
        unsigned short ip_id;
        unsigned char ip_frag_offset:5;
        unsigned char ip_more_fragment:1;
        unsigned char ip_dont_fragment:1;
        unsigned char ip_reserved_zero:1;
        unsigned char ip_frag_offset1;
        unsigned char ip_ttl;
        unsigned char ip_protocol;
        unsigned short ip_checksum;
        struct in_addr ip_srcaddr;
        struct in_addr ip_destaddr;
};
 
 
struct tcp_header
{
        unsigned short source_port;
        unsigned short dest_port;
        unsigned int sequence;
        unsigned int acknowledge;
        unsigned char ns:1;
        unsigned char reserved_part1:3;
        unsigned char data_offset:4;
        unsigned char fin:1;
        unsigned char syn:1;
        unsigned char rst:1;
        unsigned char psh:1;
        unsigned char ack:1;
        unsigned char urg:1;
        unsigned char ecn:1;
        unsigned char cwr:1;
        unsigned short window;
        unsigned short checksum;
        unsigned short urgent_pointer;
};
