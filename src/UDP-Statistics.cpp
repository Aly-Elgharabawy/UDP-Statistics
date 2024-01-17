#include <iostream>
#include <unistd.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <cstring>
#include <limits>
#include <ctime>
#include "../include/PacketManager.hpp"
#include <signal.h>
#include <sstream>
#include <string>

/*
UDP Statistics

This is a program that sniffs UDP packets and displays statistics for incoming UDP packets for each 1 second window
MUST BE RUN AS SUPERUSER

Statistics:
Total packet size in bytes
Number of packets
Average packet size
Average bitrate
Average shannon entropy for UDP payload data

The above statistics can provide useful UDP stream metadata to help classify a UDP stream (e.g. video streaming, voice chat, online gaming etc.)

NOTE: For the moment, streams are ~1 second windows that are not separated by source IP or port

*/

pcap_if_t *devices = NULL; // list of devices

// wrapper function for packet manager class's packet handler, takes char* of pointer to PacketManager instance in user_data
void pkt_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet_data)
{

    PacketManager *pkt_manager = reinterpret_cast<PacketManager *>(user_data);

    pkt_manager->pkt_handler(NULL, pkthdr, packet_data);
}
// function to make sure devices are freed on ctrl+c
void signal_callback_handler(int signum)
{
    std::cout << std::endl;
    std::cout << "Program Exiting..." << std::endl;
    pcap_freealldevs(devices);
    std::cout << "Devices Freed!" << std::endl;
    exit(signum);
}

int main(int argc, char *argv[])
{

    PacketManager pkt_manager = PacketManager(); // packet manager class to handle packet data and provide statistics
    pcap_t *handle;                              // packet capture handle
    char errbuf[PCAP_ERRBUF_SIZE];               // error buffer
    bpf_u_int32 netp;                            // ip
    bpf_u_int32 maskp;                           // subnet mask
    bpf_program filter;                          // filter program to filter packets according to set criteria

    // set callback function such that devices are freed on ctrl+c
    signal(SIGINT, signal_callback_handler);

    struct ifaddrs *ifap;
    struct sockaddr_in *addr;

    // find interface to sniff, first interface automatically picked
    // TODO add option to select interface
    if (pcap_findalldevs(&devices, errbuf) != 0)
    {
        std::cout << "ERROR: " << errbuf << std::endl;
        std::cout << "Try sudo UDP-Statistics" << std::endl;
        return 1;
    }
    // obtain host ip address and hold in str_ip_addr
    char *str_ip_addr;
    if (getifaddrs(&ifap) == 0)
    {
        for (struct ifaddrs *ifa = ifap; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_INET)
            {
                addr = (struct sockaddr_in *)ifa->ifa_addr;
                if (strcmp(ifa->ifa_name, devices->name) == 0)
                {
                    str_ip_addr = inet_ntoa(addr->sin_addr);
                }
            }
        }
    }
    // create filter string to set filtering criteria
    // Filters: UDP, not DNS, destination is host ip address
    char filter_string[54] = "udp src port not 53 and dst host ";
    //append ip address to filter string
    strncat(filter_string, str_ip_addr, 16);
    std::cout << filter_string << std::endl;
    // obtain pcap handle
    handle = pcap_open_live(devices->name, BUFSIZ, 0, -1, errbuf);
    if (handle == NULL)
    {
        std::cout << "ERROR: " << errbuf << std::endl;
        return 1;
    }
    // obtain device ip and mask
    if (pcap_lookupnet(devices->name, &netp, &maskp, errbuf) == PCAP_ERROR)
    {
        std::cout << "ERROR: " << errbuf << std::endl;
        return 1;
    }

    // compile filter string into code and store in bpf_filter
    if (pcap_compile(handle, &filter, filter_string, (int)netp, maskp) == PCAP_ERROR)
    {
        std::cout << "ERROR: " << errbuf << std::endl;
        return 1;
    }
    // bind filter to handle
    if (pcap_setfilter(handle, &filter) == PCAP_ERROR)
    {
        std::cout << "ERROR: " << errbuf << std::endl;
        return 1;
    }
    /*callback on packet capture set to pkt_handler, which is a wrapper for packet
    manager class's onpacketcapture callback function. This is done via passing the pointer
    to the PacketManager instance as a char*
    */
    // start packet capture loop
    std::cout << "--------------------Start---------------------" << std::endl;
    if (pcap_loop(handle, -1, pkt_handler, (u_char *)(&pkt_manager)) < 0)
    {
        std::cout << "loop failed: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    return 0;
}