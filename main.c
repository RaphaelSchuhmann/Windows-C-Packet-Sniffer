#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <time.h>

// -----------------------------
// Ethernet header (14 bytes)
// -----------------------------
typedef struct eth_hdr 
{
    u_char dst[6];   // Destination MAC
    u_char src[6];   // Source MAC
    u_short type;    // EtherType (0x0800 = IPv4)
} eth_hdr;

// -----------------------------
// IPv4 header (variable size, min 20 bytes)
// -----------------------------
typedef struct ipv4_hdr 
{
    u_char ver_ihl;   // Version (4 bits) + IHL (4 bits)
    u_char tos;       // Type of Service
    u_short tot_len;  // Total length (IP header + payload)
    u_short id;       // Identification
    u_short frag_off; // Fragment offset
    u_char ttl;       // Time to live
    u_char proto;     // Protocol (6 = TCP)
    u_short checksum; // Header checksum
    u_long saddr;     // Source IP
    u_long daddr;     // Destination IP
} ipv4_hdr;

// -----------------------------
// TCP header (min 20 bytes)
// -----------------------------
typedef struct tcp_hdr 
{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_long seq;             // Sequence number
    u_long ack;             // Acknowledgment number
    u_char data_off_reserved; // Data offset (4 bits) + reserved (4 bits)
    u_char flags;           // TCP flags (SYN, ACK, etc.)
    u_short win;            // Window size
    u_short sum;            // Checksum
    u_short urg;            // Urgent pointer
} tcp_hdr;

// -----------------------------
// Helper: Print MAC address in human-readable form
// -----------------------------
void print_mac(const u_char *mac) 
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1] ,mac[2] ,mac[3] ,mac[4] ,mac[5]);
}

// -----------------------------
// Helper: Print first 'max' bytes of payload in hex
// -----------------------------
void hex_preview(const u_char *data, int len, int max) 
{
    for (int i = 0; i < len && i < max; i++) 
    {
        printf("%02X ", data[i]);
    }
    if (len > max) printf("...");
}

// -----------------------------
// Callback function: called by pcap_loop for every captured packet
// -----------------------------
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt) 
{
    (void)param; // unused parameter

    // Ensure packet is at least Ethernet header size
    if (header->caplen < sizeof(eth_hdr)) return;

    //  Parse Ethernet header
    const eth_hdr *eth = (const eth_hdr*)pkt;

    // Only handle IPv4 packets (EtherType 0x0800)
    if (ntohs(eth->type) != 0x0800) return;

    // Parse IP header (offset by Ethernet header)
    const ipv4_hdr *ip = (const ipv4_hdr*)(pkt + sizeof(eth_hdr));
    int ihl = (ip->ver_ihl & 0x0F) * 4; //IP header length in bytes
    
    // Only handle TCP packets (protocol 6)
    if (ip->proto != 6) return;

    // Parse TCP header (offset by IP header length)
    const tcp_hdr *tcp = (const tcp_hdr*)((const u_char*)ip + ihl);
    int tcp_len = ((tcp->data_off_reserved >> 4) & 0x0F) * 4; // TCP header length in bytes

    // Calculate payload pointer and length
    const u_char *payload = (const u_char*)tcp + tcp_len;
    int payload_len = ntohs(ip->tot_len) - ihl - tcp_len;
    if (payload_len < 0) payload_len = 0;

    // -----------------------------
    // Print timestamp
    // -----------------------------
    struct tm tm_info;
    char buf[64];
    time_t t = header->ts.tv_sec;
    localtime_s(&tm_info, &t);
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm_info);
    printf("[%s.%06ld] ", buf, header->ts.tv_usec);

    // -----------------------------
    // Print MAC addresses
    // -----------------------------
    print_mac(eth->src); 
    printf(" -> ");
    print_mac(eth->dst); printf(" ");

    // -----------------------------
    // Print IP addresses + ports
    // -----------------------------
    char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, s_ip, sizeof(s_ip)); 
    inet_ntop(AF_INET, &ip->daddr, d_ip, sizeof(d_ip));
    printf("%s:%u -> %s:%u ", s_ip, ntohs(tcp->sport), d_ip, ntohs(tcp->dport));

    // -----------------------------
    // Print TCP flags
    // -----------------------------
    printf("[");
    if (tcp->flags & 0x02) printf("SYN "); // Synchronize: start a TCP connection (handshake step 1)
    if (tcp->flags & 0x10) printf("ACK "); // Acknowledgment: confirms receipt of packets
    if (tcp->flags & 0x01) printf("FIN "); // Finish: request to close the TCP connection
    if (tcp->flags & 0x04) printf("RST "); // Reset: immediately terminate the connection (abnormal)
    if (tcp->flags & 0x08) printf("PSH "); // Push: tells receiver to push buffered data to application immediately
    printf("] ");
        
    // -----------------------------
    // Print payload length and preview
    // -----------------------------
    printf("len=%d data=", payload_len);
    if (payload_len > 0) hex_preview(payload, payload_len, 16);
    else printf("<none>");

    printf("\n");
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    // -----------------------------
    // Find all network devices
    // -----------------------------
    if (pcap_findalldevs(&alldevs, errbuf) == -1) 
    {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // -----------------------------
    // Pick device: either from argv or first device
    // -----------------------------
    if (argc > 1) 
    {
        // Use adapter by name
        for (dev = alldevs; dev; dev = dev->next) 
        {
            if (strcmp(dev->name, argv[1]) == 0) break;
        }

        // Exit program if no device was found
        if (!dev) 
        {
            fprintf(stderr, "Device %s not found.\n", argv[1]);
            return 1;
        }
    }
    else 
    {
        dev = alldevs; // default to first device
    }

    // -----------------------------
    // Get network info (optional, needed for BPF filter)
    // -----------------------------
    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1) {
        net = 0; mask = 0;
    }

    
    // -----------------------------
    // Open device for packet capture
    // -----------------------------
    printf("Opening %s...\n", dev->name);
    handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // -----------------------------
    // Compile and apply TCP filter
    // -----------------------------
    if (pcap_compile(handle, &fp, "tcp", 0, net) == -1) {
        fprintf(stderr, "bad filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Filter error: %s\n", pcap_geterr(handle));
        return 1;
    }

    // -----------------------------
    // Start capture loop (blocks until Ctrl-C)
    // -----------------------------
    printf("Listening on %s (TCP only)...\n", dev->name);
    pcap_loop(handle, 0, packet_handler, NULL);

    // -----------------------------
    // Cleanup
    // -----------------------------
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}