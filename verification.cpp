#include <pcap.h>
#include <iostream>
#include <regex>
#include <stdlib.h>
#include <string.h>

using namespace std;

void check_interface(char *interface) 
{
    pcap_if_t *devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int check = 0;
    if (-1 == pcap_findalldevs(&devs, errbuf))
    {
        cout << "Couldn't open device list: " << errbuf << endl;
        exit(1);
    }
    if (!devs) {
        cout << "No devices found." << endl;
        exit(1);
    }
    for (pcap_if_t *d = devs; d; d = d->next) {
        if(!strcmp(d->name, interface))
            check++;
    }
    pcap_freealldevs(devs);

    if(!check){
        cout << "\033[1;34m[-] Error : interface is not exist... Check it plz.\033[0m" << endl;
        cout << "\033[1;32m[-] Usage: send_arp <interface> <sender(victim) ip> <target ip> \033[0m" << endl <<\
                "\033[1;31m[-] ex) send_arp wlan0 192.168.10.2 192.168.10.1\033[0m\n";
        exit(1);
    }
}

void check_ipaddr(char source[16], char destination[16])
{
    regex reg("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    smatch source_match;
    smatch dst_match;
    std::string source_ip(source);
    std::string dst_ip(destination);
    if( !regex_match(source_ip, source_match, reg)){
        cout << "\033[1;34m[-] Error : ip address is strange... Check it plz.\033[0m" << endl;
        cout << "\033[1;32m[-] Usage: send_arp <interface> <sender(victim) ip> <target ip> \033[0m" << endl <<\
                "\033[1;31m[-] ex) send_arp wlan0 192.168.10.2 192.168.10.1\033[0m\n";
        exit(1);
    }
    if( !regex_match(dst_ip, dst_match, reg)){
        cout << "\033[1;34m[-] Error : ip address is strange... Check it plz.\033[0m" << endl;
        cout << "\033[1;32m[-] Usage: send_arp <interface> <sender(victim) ip> <target ip> \033[0m" << endl <<\
                "\033[1;31m[-] Ex)send_arp wlan0 192.168.10.2 192.168.10.1\033[0m\n";
        exit(1);
    }
}
