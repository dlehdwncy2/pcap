#include <pcap/pcap.h> 
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/ip.h>  
#include <netinet/in.h>  
#include <netinet/tcp.h>
#include <netinet/udp.h>

char track[] = "Forensic"
char name[] = "Lee_Dong_Ju";
printf("[bob7][%s]pcap_test[%s]", track, name)


int main(int argc, char* argv[]) {

	if (argc !=2){
		return -1;
	}
	struct in_addr host_ip;
	int res;
	char* dev=argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); 

	while (true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		res=pcap_next_ex(handle,&header,&packet);
		if (res == 0) continue;
   		if (res == -1 || res == -2) break;

		struct ether_header *ehP = (struct ether_header*)packet;
		packet+=sizeof(ether_header);
		struct iphdr *iph = (struct iphdr*)packet;
		packet+=sizeof(iphdr);
		struct tcphdr *tcph = (struct tcphdr*)packet;
		packet+=sizeof(tcph);

	 	printf("Ethernet\n");
	 	printf("SORUCE\t->\tDestination\n");
		printf("[%02X:%02X:%02X:%02X:%02X:%02X "
		 	"-> %02X:%02X:%02X:%02X:%02X:%02X]\n",
		 	    ehP->ether_shost[0],
	     		ehP->ether_shost[1],
	     		ehP->ether_shost[2],
	     		ehP->ether_shost[3],
	     		ehP->ether_shost[4],
	     		ehP->ether_shost[5],
	     
	     		ehP->ether_dhost[0],
	     		ehP->ether_dhost[1],
	     		ehP->ether_dhost[2],
	     		ehP->ether_dhost[3],
	     		ehP->ether_dhost[4],
	     		ehP->ether_dhost[5]);
		printf("Next Protocol : ");

		switch(ntohs(ehP->ether_type))
		{
			case ETHERTYPE_IP:
			printf("\t\t[IP]\t\t\n");
			printf("\tversion\t: %d\n", iph->version);  
    		printf("\tLength\t : %d Bytes\n", (iph->ihl)<<2);  
    		printf("\tService\t: %X\n", ntohs(iph->tos));  
   		 	printf("\tlength\t: %04d Bytes\n", ntohs(iph->tot_len));  
		    printf("\tID\t\t: %d\n", ntohs(iph->id));  
		    printf("\tFragment_offset\t\t: 0x%04X\n", ntohs(iph->frag_off));  
		    printf("\tTTL\t\t: %d sec\n", iph->ttl);  
		    printf("\tCHECKSUM\t\t: %d\n", iph->check);
		    printf("\tprotocol\t\t: %d\n", iph->protocol);


		    host_ip.s_addr=iph->saddr;
			printf("SRC_ADDR \t: %s\n", inet_ntoa(host_ip));
			host_ip.s_addr=iph->daddr;
			printf("DST_ADDT \t: %s\n", inet_ntoa(host_ip));
		    switch(iph->protocol)  
		    {  
		        case 6: 
		            printf("\t[TCP]\t\n");  
		           	printf("SRC_PORT : %d\n", tcph->source); 
		           	printf("DST_PORT : %d\n", tcph->dest);
		           	printf("Data : ");
		           	for (unsigned int index=0; index<16; index++){
		           		if (packet[index]==NULL){
		           			break;
		           		}
		           		printf("%x ",packet[index]);
		           	}
		            break;  
		        case 17:   	
		            printf("\t[UDP[\n");  
		            printf("SRC_PROTOCOL\t: %d\n", tcph->source); 
		           	printf("DST_PROTOCOL\t: %d\n", tcph->dest);  
		            break;  
		        default:  
		            printf("PROTOCOL\t\t: %d\n", iph->protocol);  
		            break;  
		    }  

		    break;
		    case ETHERTYPE_ARP:
		    printf("[ARP]\t\n");
		    break;
		    case ETHERTYPE_REVARP:
		    printf("[Reverse ARP]\t\n");
		    break;
		    default:
		    printf("[DEFAULT]\n");
		    break;
		}
	}
	pcap_close(handle);
	return 0;
}