#include <iostream>
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
#include "Accumulators.hpp"
/*
Packet Manager Class
This class handles packet data as packets come in. It is responsible for holding accumulators for different metrics
and displaying + refreshing metrics for each stream.


NOTE: For the moment, streams are ~1 second windows that are not separated by source IP or port
*/
class PacketManager
{
public:
    // accumulators, timestamp variable
    SizeAccumulator size_acc;
    EntropyAccumulator entropy_acc;
    std::time_t stamp;

    // constructor
    PacketManager()
    {
        size_acc = SizeAccumulator();
        entropy_acc = EntropyAccumulator();
        stamp = std::time(nullptr);
    }
    /*
    Packet Handler function

    Callback function on packet sniff.

    Calls accumulators to process packet data
    Prints statistics if more than one second elapsed between last print and packet received

    */
    void pkt_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet_data)
    {
        size_acc.accumulate(pkthdr, packet_data);
        entropy_acc.accumulate(pkthdr, packet_data);

        if (std::time(nullptr) - stamp > 1)
        {
            std::time(&stamp);
            print_data();
            size_acc.reset();
            entropy_acc.reset();
        }
    }
    void print_data()
    {
        std::cout << "--------------------Statistics---------------------" << std::endl;
        std::cout << "Size: " << size_acc.get_data() << "bytes" << std::endl;
        std::cout << "Number of Packets: " << size_acc.get_n_packets() << "packets" << std::endl;
        std::cout << "Average Size: " << size_acc.get_avg_size() << "bytes" << std::endl;
        std::cout << "Bitrate: " << size_acc.get_bitrate() << " kB/s" << std::endl;
        std::cout << "Entropy: " << entropy_acc.get_data() << std::endl;
    }
};