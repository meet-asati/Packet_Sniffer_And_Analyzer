#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

void callback(unsigned char *user, const struct pcap_pkthdr *pkthdr,
              const unsigned char *packet)
{
    int len = pkthdr->len;

    for (int i = 0; i < len; i++)
    {
        printf("%02x ", packet[i]);
    }
    printf("\n");

    printf("Src MAC: %02x %02x %02x %02x %02x %02x\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    printf("Dest MAC: %02x %02x %02x %02x %02x %02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);

    printf("EtherType: %02x %02x ", packet[12], packet[13]);
    if (packet[12] == 0x08 && packet[13] == 0x00)
        printf("(IPv4)");
    else if (packet[12] == 0x86 && packet[13] == 0xDD)
        printf("(IPv6)");
    printf("\n");

    printf("Src IP: %02x %02x %02x %02x\n", packet[26], packet[27], packet[28], packet[29]);
    printf("Dest IP: %02x %02x %02x %02x\n", packet[30], packet[31], packet[32], packet[33]);
    printf("Protocol: ");
    if(packet[23] == 0x11) 
        printf("UDP");
    else if (packet[23] == 0x06)
        printf("TCP");
    printf("\n");

    int header_length = (packet[14] & 0x0F) * 4;

    printf("IP Header Length: %d bytes\n", header_length);
}

int main(int argc, char const *argv[])
{
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char err_buff[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, err_buff) == -1)
    {
        fprintf(stderr, "Error executing pcap_findalldevs: %s\n", err_buff);
        exit(1);
    }

    if (alldevs == NULL)
    {
        printf("No capture devices found.\n");
        exit(1);
    }

    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        printf("\nDevice Name: %s\n", dev->name);
        if (dev->description)
            printf("Description: %s\n", dev->description);
        else
            printf("Description: No description available\n");

        int pckts_cnt = 1;

        pcap_t *capdev = pcap_open_live(dev->name, BUFSIZ, 0, -1, err_buff);

        if (capdev == NULL)
        {
            printf("ERR: pcap_open_live() %s\n", err_buff);
            exit(1);
        }

        if (pcap_loop(capdev, pckts_cnt, callback, (unsigned char *)NULL))
        {
            printf("ERR: pcap_loop() failed!\n");
            exit(1);
        }
    }

    pcap_freealldevs(alldevs);
    return 0;
}