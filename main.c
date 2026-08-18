#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

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
            printf("Description: %s\n\n", dev->description);
        else 
            printf("Description: No description available\n\n");
    }

    pcap_freealldevs(alldevs);
    return 0;
}