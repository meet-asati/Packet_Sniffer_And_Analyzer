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
        printf("Device Name: %s\n", dev->name);
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