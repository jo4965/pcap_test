#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet);

void chtoMac(const u_char * mac);

int main(void)
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct in_addr net_addr, mask_addr;

    struct bpf_program fp;

    pcap_t *pcd;  // packet capture descriptor

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Interface : %s\n", dev);

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("NET : %s\n", net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("Subnet Mask : %s\n", mask);
    printf("=======================\n");

    pcd = pcap_open_live(dev, BUFSIZ,  1, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    if (pcap_compile(pcd, &fp, NULL, 0, netp) == -1)
    {
        printf("compile error\n");
        exit(1);
    }

    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);
    }

    pcap_loop(pcd, 0, callback, NULL); // packet capture occurs 2nd argument times;
}


void chtoMac(const u_char * mac) // change mac address from byte_array to AA:BB:CC:DD:FF:GG
{
    for(int i = 0 ; i < 5 ; i++)
    {
        printf("%02x:", *mac);
        mac++;
    }
    printf("%02x\n", *mac);

}


/*
     I wrote down codes with naive methods using my own offset structures(following one).
     The variables contain offsets from the beginning of the frame.
*/
struct MY_OFFSET{
    unsigned int mac_src, mac_dst;
    unsigned int ether_size;
    unsigned int ether_type;
    unsigned int ip_src, ip_dst;
    unsigned int ip_size;
    unsigned int dport, sport;
};

/*
    For approaching data which is less than 1 byte like 4bit,
    following MY_OFFSET_BIT structure is needed.
*/
struct MY_OFFSET_BIT{
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned int ihl:4;       /* header length */
        unsigned int version:4;        /* version */
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
        unsigned int version:4;        /* version */
        unsigned int ihl:4;       /* header length */
    #endif
};




struct ip* iph;
struct tcphdr* tcph;
struct udphdr * udph;
struct arphdr * arph;
struct MY_OFFSET myoff = {6, 0, 14, 12, 14 + 12, 14 + 16, 0, 0, 0};


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet)
{
    unsigned short ether_type;
    u_char IP_type;

    int chcnt;
    int length= pkthdr->len;


    printf("PACKET CAPTURED\n");


    printf("Src MAC Address : ");
    chtoMac((packet + myoff.mac_src));
    printf("Dst MAC Address : ");
    chtoMac((packet + myoff.mac_dst));
    printf("\n");

    // Type of upper protocol

    ether_type = ntohs(*(uint16_t *)(packet + myoff.ether_type));

    // In case : IP
    if (ether_type == ETHERTYPE_IP)
    {
        //myoff IP initialize
        printf("This is IP Packet\n");
        printf("Src IP Address : %s\n", inet_ntoa(*(struct in_addr *)(packet + myoff.ip_src)));
        printf("Dst IP Address : %s\n", inet_ntoa(*(struct in_addr *)(packet + myoff.ip_dst)));
        printf("\n");

        // In case : TCP
        IP_type = *(u_char *)(packet + myoff.ether_size + 9);
        if (IP_type == IPPROTO_TCP)
        {
            //myoff TCP initialize
            //I used myoffbit structure for less than 1 byte pointer shifting.
            myoff.ip_size = ((struct MY_OFFSET_BIT * )(packet + myoff.ether_size))->ihl;
            myoff.sport = myoff.ip_size * 4 + myoff.ether_size;
            myoff.dport = myoff.ip_size * 4 + myoff.ether_size + 2;

            printf("with TCP\n");
            printf("Src Port : %d\n" , ntohs(*(uint16_t *)(packet + myoff.sport)));
            printf("Dst Port : %d\n" , ntohs(*(uint16_t *)(packet + myoff.dport)));
            printf("\n");
        }
        // In case : UDP
        else if(IP_type == IPPROTO_UDP)
        {
            udph = (struct udphdr *)(packet + myoff.ether_size);
            printf("with UDP\n");

            printf("Src Port : %d\n" , ntohs((udph->uh_sport)));
            printf("Dst Port : %d\n" , ntohs((udph->uh_dport)));
            printf("\n");
        }
        else if(IP_type == IPPROTO_ICMP)
            printf("with ICMP\n");
        else if(IP_type == IPPROTO_IGMP)
            printf("with IGMP\n");
        else
            printf("Unknown Packet");

    }
    // In case : ARP
    else if(ether_type == ETHERTYPE_ARP)
    {
        arph = (struct arphdr *) (packet + myoff.ether_size);

        if(arph -> ar_op == 0x0001)
            printf("ARP Request\n");
        else
            printf("ARP Reply\n");

    }
    // The other cases :
    else
    {
        printf("Unknown Frame\n");
    }

    // Print all the byte array.
    printf("The size of the packet : %d ", length);
    printf("bytes\n");


    printf("Raw Data :\n");

    chcnt = 0;
    while(length--)
    {
        printf("%02x ", *(packet++));
        if ((++chcnt % 16) == 0)
            printf("\n");
    }

    printf("\n==============================================\n");
    printf("\n\n");
}
