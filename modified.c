#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {

        // Conditional to see if packet can contain Ethernet and IP headers, if not returns error
        if (header.len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    		fprintf(stderr, "Packet %d too small for Ethernet and IP headers\n", packet_count+1);
    		continue;
    	}

        ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

        // Storing destination addresses in new variable
        struct in_addr ip_dst; 
        ip_dst.s_addr = ip_header->daddr; 

        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(*((struct in_addr*)ip_header->daddr)));
    }

    pcap_close(handle);
    return 0;
}
