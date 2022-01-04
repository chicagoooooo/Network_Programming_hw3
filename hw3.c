#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <time.h>
#include <netinet/udp.h>

int cnt=1;
char *ip_ntoa(void *i,int version);
char *ip_ttoa(u_int8_t flag);
char *ip_ftoa(u_int16_t flag);
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content);
void print_TCP_table(struct tcphdr *tcp);
void print_UDP_table(struct udphdr *udp);
void print_ethhdr_table(struct ether_header *ethernet_protocol);
void print_ip4_table(struct ip *ip,const u_char *packet_content);
void print_ip6_table(struct ip6_hdr *ip6,const u_char *packet_content);
void print_boundary();
char *tcp_ftoa(u_int8_t flag);

int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    if(argc!= 2){
        printf("wrong argc number\n");
        printf("usage : ./hw3 [filename]\n");
        exit(1);
    }
    char filename[32];
    strcpy(filename,argv[1]);
    handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        exit(1);
    }//end if

    //read from file
    if(-1 == pcap_loop(handle, -1, pcap_callback, NULL)) {
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));
    }//end if

    //free
    pcap_close(handle);

    return 0;
}

void pcap_callback(u_char *argument, const struct pcap_pkthdr *packet_heaher, const u_char *packet_content) {
    //packet
    print_boundary();
    printf("NO.%d packet\n\n",cnt++);			
    printf("packet header\n");
	printf("\tTime Stamp : %s", ctime((time_t *)&(packet_heaher->ts.tv_sec))); //轉換時間
    printf("\tlen : %d\n",packet_heaher->len);
    printf("\tcaplen : %d\n",packet_heaher->caplen);

    //get ether_header
    struct ether_header *ethernet_protocol;
	ethernet_protocol = (struct ether_header *)packet_content;
    print_ethhdr_table(ethernet_protocol);

    //get ip
    struct ip *ip = (struct ip *)(packet_content + ETHER_HDR_LEN);
	u_char protocal = ip->ip_p;

	unsigned short ethernet_type;			//乙太網型別
	ethernet_type = ntohs(ethernet_protocol->ether_type);//獲得乙太網的型別
    if(ethernet_type == ETHERTYPE_IP){
        print_ip4_table(ip,packet_content);
    }else if(ethernet_type==ETHERTYPE_IPV6){
        struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet_content + ETHER_HDR_LEN);
        print_ip6_table(ip6,packet_content);
    }else if(ethernet_type==ETHERTYPE_AARP){
        printf("Ether_type : AARP\n");
    }else if(ethernet_type==ETHERTYPE_ARP){
        printf("Ether_type : ARP\n");
    }else if(ethernet_type==ETHERTYPE_PUP){
        printf("Ether_type : PUP\n");
    }else if(ethernet_type==ETHERTYPE_REVARP){
        printf("Ether_type : REVARP\n");
    }else{
        printf("Can't recognize this ETHERTYPE :(\n");
    }
    print_boundary();
}

char *ip_ntoa(void *i,int version) {//inet_ntoa just use in ipv4 so i don't use it
    static char str[INET_ADDRSTRLEN];
    static char ip6[INET6_ADDRSTRLEN]; // 儲存 IPv6 字串的空間
    if(version==4){
        inet_ntop(AF_INET, i, str, sizeof(str));
    }else if(version==6){
        inet_ntop(AF_INET6, i, ip6, INET6_ADDRSTRLEN);
    }else{
        printf("Version error!\n");
    }

    if(version==4){
        return str;
    }else if(version==6){
        return ip6;
    }else return NULL;
    
}//end ip_ntoa


void print_TCP_table(struct tcphdr *tcp){
    u_int16_t src_port = ntohs(tcp->th_sport);
    u_int16_t dest_port = ntohs(tcp->th_dport);
    u_int32_t seq_num = ntohl(tcp->th_seq);
    u_int32_t ack_num = ntohl(tcp->th_ack);
    u_int8_t hdr_len = tcp->th_off<<2;
    u_int8_t flags = tcp->th_flags;
    u_int16_t win = ntohs(tcp->th_win); 
    u_int16_t checksum = ntohs(tcp->th_sum);
    u_int16_t urp = ntohs(tcp->th_urp);
    printf("Protocol : TCP\n");
    printf("\tSource Port            : %u\n", src_port);
    printf("\tDestination Port       : %u\n", dest_port);
    printf("\tSequence number        : %u\n",seq_num);
    printf("\tAcknowledgement number : %u\n",ack_num);
    printf("\tHeader length          : %u\n",hdr_len);
    printf("\tFlags                  : %s\n",tcp_ftoa(flags));
    printf("\twindow                 : %u\n",win);
    printf("\tchecksum               : %u\n",checksum);
    printf("\turgent pointer         : %u\n",urp);
}

void print_UDP_table(struct udphdr *udp){
    u_int16_t src_port = ntohs(udp -> uh_sport);
    u_int16_t dest_port = ntohs(udp -> uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);
    printf("Protocol : UDP\n");
    printf("\tSource Port      : %u\n", src_port);
    printf("\tDestination Port : %u\n", dest_port);
    printf("\tLength           : %u\n",len);
    printf("\tCheck sum        : %u\n",checksum);
}


void print_ethhdr_table(struct ether_header *ethernet_protocol){
    unsigned char *mac_string;
    mac_string = (unsigned char *)ethernet_protocol->ether_shost;//獲取源mac地址
    printf("Ether header\n");
	printf("\tMac Source Address      : %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//獲取目的mac
	printf("\tMac Destination Address : %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	printf("\tEthernet type           : %04x\n",ntohs(ethernet_protocol->ether_type));
}


void print_ip4_table(struct ip *ip,const u_char *packet_content){
    printf("Ether_type is IPv4\n");
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_char tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);//net to host short
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_char ttl = ip->ip_ttl;
    u_char protocal = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);
    printf("\tSource IP Address      : %s\n",  ip_ntoa(&ip->ip_src,version));
    printf("\tDestination IP Address : %s\n", ip_ntoa(&ip->ip_dst,version));
    printf("\tversion                : %u\n",version);
    printf("\theader length          : %u\n",header_len);
    printf("\tType of Service        : %s\n",ip_ttoa(tos));//type of service convert to string
    printf("\tTotal Length           : %u\n",total_len);
    printf("\tIdentifer              : %u\n",id);
    printf("\tFlags                  : %s\n",ip_ftoa(offset));
    printf("\tFragmented Offset      : %u\n",offset & IP_OFFMASK);
    printf("\tTime to Live           : %u\n",ttl);
    printf("\tProtocal               : %u\n",protocal);
    printf("\tHeader Checksum        : %u\n",checksum);
    if(protocal == IPPROTO_TCP){
        struct tcphdr *tcp = (struct tcphdr *)(packet_content + ETHER_HDR_LEN + (ip->ip_hl << 2));//ip 4bytes 1 word
        print_TCP_table(tcp);
    }else if(protocal == IPPROTO_UDP){
        struct udphdr *udp = (struct udphdr *)(packet_content + ETHER_HDR_LEN + (ip->ip_hl << 2));
        print_UDP_table(udp);
    }else {
        printf("Can't recognize this protocal\n");
    }
    
}


void print_ip6_table(struct ip6_hdr *ip6,const u_char *packet_content){
    printf("Ether_type : IPv6\n");
    printf("\tSource IP Address      : %s\n",  ip_ntoa(&ip6->ip6_src,6));
    printf("\tDestination IP Address : %s\n", ip_ntoa(&ip6->ip6_dst,6));
    u_int32_t flow_label = ntohl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow);
    u_int8_t hop_limit = ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
    u_int8_t next_hdr = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    u_int16_t payload_len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
    u_int8_t vfc = ip6->ip6_ctlun.ip6_un2_vfc;
    printf("\tFlow Label             : %u\n",flow_label);
    printf("\tHop Limit              : %u\n",hop_limit);
    printf("\tNext Header            : %u\n",next_hdr);
    printf("\tPayload Length         : %u\n",payload_len);
    printf("\tVFC                    : %u\n",vfc);
    if(next_hdr==IPPROTO_TCP){
        struct tcphdr *tcp = (struct tcphdr *)(packet_content+ ETHER_HDR_LEN + sizeof(struct ip6_hdr));
        print_TCP_table(tcp);
    }else if(next_hdr==IPPROTO_UDP){
        struct udphdr *udp = (struct udphdr *)(packet_content+ ETHER_HDR_LEN + sizeof(struct ip6_hdr));
        print_UDP_table(udp);
    }else {
        printf("Can't recognize this protocal\n");
    }
}

void print_boundary(){
    printf("-----------------------------------------------------\n");
}


char *ip_ftoa(u_int16_t flag) {
    static int f[] = {'R', 'D', 'M'}; //flag
#define IP_FLG_MAX (sizeof(f)/sizeof(f[0]))
    static char str[IP_FLG_MAX + 1]; //return buffer
    u_int16_t mask = 1 << 15; //mask
    int i;

    for(i = 0 ; i < IP_FLG_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ftoa

char *ip_ttoa(u_int8_t flag) {
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
#define TOS_MAX (sizeof(f)/sizeof(f[0]))
    static char str[TOS_MAX + 1]; //return buffer
    u_int8_t mask = 1 << 7; //mask
    int i;

    for(i = 0 ; i < TOS_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;

    return str;
}//end ip_ttoa


char *tcp_ftoa(u_int8_t flag) {
    static int  f[] = {'W', 'E', 'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof f / sizeof f[0])
    static char str[TCP_FLG_MAX + 1];
    u_int32_t mask = 1 << 7;
    int i;

    for (i = 0; i < TCP_FLG_MAX; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = '\0';

    return str;
}//end tcp_ftoa
