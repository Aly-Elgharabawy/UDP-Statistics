#include <iostream>
#include <pcap.h>
#include <sys/time.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <math.h>
/*
Accumulators: Classes that process incoming packet data to provide UDP stream metadata
(For the moment, streams are ~1 second windows that do not separate by source IP or port)

e.g. SizeAccumulator        --> Total stream size, bitrate, average packet size etc.
     Entropy Accumulator    --> Average Shannon Entropy for each stream's UDP payload data

*/

// create accumulator interface
template <typename T>
class Accumulator
{
public:
    virtual void accumulate(const struct pcap_pkthdr *pkthdr, const unsigned char *packet_data) = 0;
    virtual void reset() = 0;
    virtual T get_data() = 0;
};

/*
SizeAccumulator
An accumulator class responsible for statistics pertaining to packet size:

Statistics:
Total packet size in bytes
Number of packets
Average packet size
Largest/Smallest packet in stream
Average bitrate
*/
class SizeAccumulator : public Accumulator<u_int32_t>
{
public:
    u_int32_t total_size;
    u_int32_t largest;
    u_int32_t smallest;
    u_int32_t n_packets;
    struct timeval first;
    struct timeval last;

    // constructor
    SizeAccumulator()
    {
        total_size = 0;
        n_packets = 0;
        largest = 0;
        smallest = 65515;
        first = {0, 0};
        last = {0, 0};
    }

    /*
    Size accumulator function

    Updates:
    Total packet size
    Number of packets
    Timestamps for first and last packets in stream

    The above are used to calculate statistics pertaining to stream packet size and stream bitrate
    */
    void accumulate(const struct pcap_pkthdr *pkthdr, const unsigned char *packet_data) override
    {
        if (first.tv_sec == 0)
        {
            first = pkthdr->ts;
        }
        if (pkthdr->len > largest)
        {
            largest = pkthdr->len;
        }
        if (pkthdr->len < smallest)
        {
            smallest = pkthdr->len;
        }
        total_size = total_size + pkthdr->len;
        n_packets += 1;
        last = pkthdr->ts;
    }

    // gets the sum of the all packet sizes in stream
    u_int32_t get_data() override
    {
        return total_size;
    }
    // returns average stream bitrate in kilobytes per second
    u_int32_t get_bitrate()
    {
        u_int32_t window = last.tv_sec - first.tv_sec;
        if (window == 0)
        {
            return 0;
        }
        else
        {
            return ((total_size) / window) / 1000;
        }
    }
    // returns average packet size for stream
    u_int32_t get_avg_size()
    {
        if (n_packets == 0)
        {
            return 0;
        }
        else
        {
            return (total_size / n_packets);
        }
    }
    // returns size of largest packet in stream
    u_int32_t get_largest()
    {
        return largest;
    }
    // returns number of packets in stream
    u_int32_t get_n_packets()
    {
        return n_packets;
    }
    // returns size of smallest packet in stream
    u_int32_t get_smallest()
    {
        return smallest;
    }
    // resets variables between refreshes
    void reset() override
    {
        total_size = 0;
        n_packets = 0;
        largest = 0;
        smallest = 65515;
        first = {0, 0};
        last = {0, 0};
        first = {0, 0};
        last = {0, 0};
    }
};
/*
EntropyAccumulator
An accumulator class responsible for calculating the average shannon entropy for each stream's packets

Shannon entropy is a metric that, for the purposes of this project, measures the inherent 'randomness'
in the data content of a packet. It can take values from 0 to 8 where 8 represents the most 'random'


For each packet:
Shannon Entropy = -sum( Pi * log2(Pi) ) for i=0-->255  (if Pi = 0, skip)
where Pi is the probability of byte i's occurence in the UDP packet's payload data
Pi = (number of occurences of some byte) / (total payload size)

For stream:
Average Entropy(n+1) = [(Average Entropy(n) * n) + new packet's entropy] / [n+1]

The average UDP payload entropy for each stream can help classify the type of data being exchanged.
For instance, encrypted/compressed video streaming data would have higher average entropy than
video gaming data.
*/
class EntropyAccumulator : public Accumulator<float>
{
public:
    int n_packets;
    float avg_entropy;
    // constructor
    EntropyAccumulator()
    {
        avg_entropy = 0.0;
        n_packets = 0;
    }
    /*
    Entropy accumulator function
    calculates packet's shannon entropy and count it towards average entropy

    Step 1: Calculate offset for UDP payload data
    Step 2: Count frequency (and indirectly probability) of each byte's occurence
    Step 3: Calculate packet's shannon entropy
    Step 4: Update average packet entropy for stream

    */
    void accumulate(const struct pcap_pkthdr *pkthdr, const unsigned char *packet_data) override
    {
        float pkt_entropy = 0;
        n_packets++;
        // initialize ip header
        struct ip *ip_hdr = (struct ip *)(packet_data + sizeof(struct ether_header));
        int freq[256] = {0};
        // calculate UDP payload offset (ethernet+ip+udp headers)
        int offset = ip_hdr->ip_hl * 4 + sizeof(struct ether_header);
        // calculate size of UDP payload
        int udp_payload = pkthdr->len - (offset + 8);
        // for each byte occurence, increment frequency
        for (u_int16_t i = offset + 8; i < pkthdr->len; i++)
        {
            freq[(int)packet_data[i]]++;
        }
        // calculate sum of -Pi * log(Pi) where Pi = frequency/size of udp payload
        float log_len = log2(udp_payload);
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0)
            {
                continue;
            }
            pkt_entropy += ((float)freq[i] / (float)udp_payload) * (log_len - log2(freq[i]));
        }
        avg_entropy = ((avg_entropy) * (n_packets - 1) + pkt_entropy) / (n_packets);
    }
    // return average packet entropy for stream
    float get_data() override
    {
        return avg_entropy;
    }
    // reset variables between refreshes
    void reset() override
    {
        avg_entropy = 0;
        n_packets = 0;
    }
};
