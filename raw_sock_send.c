/*Created by Oscar Arjun singh Tark May 2020*/

//FIX ETHERNET FRAME CHECKSUM...
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include "exp.h"
#include <linux/sockios.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>

struct destination
{
	unsigned char hw1;
	unsigned char hw2;
	unsigned char hw3;
	unsigned char hw4;
	unsigned char hw5;
	unsigned char hw6;
};

unsigned int checksum(unsigned short*, int);

int main()
{
	int sockfd, totlen;
	char* buffer = (char*)malloc(64);
	if((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
		fatal("Could not open socket\n");

	struct ifreq ifreq_i, ifreq_hw, ifreq_ip;
	struct destination dest_hw;

	//SET DESTINATION MACADDR
	zero_out(&dest_hw, sizeof(struct destination));
    //INSERT YOUR DESTINATION MAC ADDRESS AS HEX HERE:
	dest_hw.hw1 = (unsigned char)(0x00);
	dest_hw.hw2 = (unsigned char)(0x00);
	dest_hw.hw3 = (unsigned char)(0x00);
	dest_hw.hw4 = (unsigned char)(0x00);
	dest_hw.hw5 = (unsigned char)(0x00);
	dest_hw.hw6 = (unsigned char)(0x00);

	zero_out(&ifreq_i, sizeof(struct ifreq));
	zero_out(&ifreq_hw, sizeof(struct ifreq));
	zero_out(&ifreq_ip, sizeof(struct ifreq));
	memset(buffer, 0, 64);

	strncpy(ifreq_i.ifr_name, "wlp3s0", IFNAMSIZ-1);
	strncpy(ifreq_hw.ifr_name, "wlp3s0", IFNAMSIZ-1);
	strncpy(ifreq_ip.ifr_name, "wlp3s0", IFNAMSIZ-1);

	if((ioctl(sockfd, SIOCGIFINDEX, &ifreq_i)) < 0)
		fatal("Unable to retrieve devices index\n");
	if((ioctl(sockfd, SIOCGIFHWADDR, &ifreq_hw)) < 0)
		fatal("Unable to retrieve HW address\n");
	if((ioctl(sockfd, SIOCGIFADDR, &ifreq_ip)) < 0)
		fatal("Error finding IPADDR");

	printf("Device ID is: %d", ifreq_i.ifr_ifindex);

	//CREATE PACKET OUT OF RETRIEVED DATA
	struct ethhdr* eth_pack = (struct ethhdr*)(buffer);
	eth_pack->h_source[0] = (unsigned char)ifreq_hw.ifr_hwaddr.sa_data[0];
	eth_pack->h_source[1] = (unsigned char)ifreq_hw.ifr_hwaddr.sa_data[1];
	eth_pack->h_source[2] = (unsigned char)ifreq_hw.ifr_hwaddr.sa_data[2];
	eth_pack->h_source[3] = (unsigned char)ifreq_hw.ifr_hwaddr.sa_data[3];
	eth_pack->h_source[4] = (unsigned char)ifreq_hw.ifr_hwaddr.sa_data[4];
	eth_pack->h_source[5] = (unsigned char)ifreq_hw.ifr_hwaddr.sa_data[5];

	eth_pack->h_dest[0] = dest_hw.hw1;
	eth_pack->h_dest[1] = dest_hw.hw2;
	eth_pack->h_dest[2] = dest_hw.hw3;
	eth_pack->h_dest[3] = dest_hw.hw4;
	eth_pack->h_dest[4] = dest_hw.hw5;
	eth_pack->h_dest[5] = dest_hw.hw6;

	printMAC("Packet Source", eth_pack->h_source[0], eth_pack->h_source[1], eth_pack->h_source[2], eth_pack->h_source[3], eth_pack->h_source[4], eth_pack->h_source[5]);
	printMAC("Packet Destination", eth_pack->h_dest[0], eth_pack->h_dest[1], eth_pack->h_dest[2], eth_pack->h_dest[3], eth_pack->h_dest[4], eth_pack->h_dest[5]);

	eth_pack->h_proto = htons(ETH_P_IP); // 0x800
	int ethhdr_total_len = sizeof(struct ethhdr);

	//BUILD IP HEADER
	struct iphdr* ip_pack = (struct iphdr*)(buffer + ethhdr_total_len);
	zero_out(ip_pack, sizeof(struct iphdr));
	ip_pack->ihl = 5;
	ip_pack->version = 4;
	ip_pack->tos = 16; // 0x10 LOWDELAY
	ip_pack->ttl = 64;
	ip_pack->protocol = IPPROTO_UDP;
	ip_pack->saddr = inet_addr(inet_ntoa(((struct sockaddr_in*)&ifreq_ip.ifr_addr)->sin_addr));
	ip_pack->daddr = inet_addr("192.168.178.35"); //Destination addr
	int ip_total_len = sizeof(struct iphdr);// + 4;

	//BUILD UDP HEADER
	struct udphdr* udp_pack = (struct udphdr*)(buffer + (ip_total_len + ethhdr_total_len));
	udp_pack->source = htons(23451);
	udp_pack->dest = htons(23451);
	udp_pack->check = 0;

	int udp_total_len = sizeof(struct udphdr);

	//SET TOTAL LENGTH
	totlen = ethhdr_total_len + ip_total_len + udp_total_len;

	buffer[totlen++] = 0xAA;
	buffer[totlen++] = 0xBB;
	buffer[totlen++] = 0xCC;
	buffer[totlen++] = 0xDD;
	buffer[totlen++] = 0xEE;

	//FINALIZE UDP AND IP HDR
	udp_pack->len = htons(totlen - ip_total_len - ethhdr_total_len);
	ip_pack->tot_len = htons(totlen - ethhdr_total_len);
	ip_pack->check = checksum((unsigned short*)(buffer + sizeof(struct ethhdr)), (sizeof(struct iphdr)/2));
	udp_pack->check = ip_pack->check;

	//SEND PACKET
	struct sockaddr_ll sadr_ll;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
	sadr_ll.sll_halen = ETH_ALEN;
	sadr_ll.sll_addr[0] = dest_hw.hw1;
	sadr_ll.sll_addr[1] = dest_hw.hw2;
	sadr_ll.sll_addr[2] = dest_hw.hw3;
	sadr_ll.sll_addr[3] = dest_hw.hw4;
	sadr_ll.sll_addr[4] = dest_hw.hw5;
	sadr_ll.sll_addr[5] = dest_hw.hw6;

	int send_len = 0;
	if((send_len = sendto(sockfd, buffer, 64, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll))) == -1)
	{
		printf("\nUnable to send packet errno=%d\n", errno);
		perror("MESSAGE");
	}

	printf("\nSent packet total_len %d", send_len);
	close(sockfd);
	return 0;
}

unsigned int checksum(unsigned short* buff, int _16bitword)
{
	unsigned long sum;
	for(sum = 0; _16bitword > 0; _16bitword--)
	{
		sum+=htons(*(buff)++);
		sum=((sum >> 16) + (sum & 0xFFFF));
		sum += (sum >> 16);
	}
	printf("\nChecksum 0x%x", htons(~sum));
	return (unsigned short)(~sum);
}
