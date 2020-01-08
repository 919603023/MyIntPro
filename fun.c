#include "fun.h"
int interface_num = 0; //接口数量

MYBUF mybuf;

INTERFACE net_interface[16]; //接口数据

ARPLIST *HEAD = NULL;

CONFIG_ROUTE_MSG *Route_Msg = NULL;

int get_interface_num()
{
	return interface_num;
}

void getinterface()
{
	struct ifreq buf[16]; /* ifreq结构数组 */
	struct ifconf ifc;	/* ifconf结构 */

	int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	/* 初始化ifconf结构 */
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = (caddr_t)buf;

	/* 获得接口列表 */
	if (ioctl(sock_raw_fd, SIOCGIFCONF, (char *)&ifc) == -1)
	{
		perror("SIOCGIFCONF ioctl");
		return;
	}
	interface_num = ifc.ifc_len / sizeof(struct ifreq); /* 接口数量 */
	printf("interface_num=%d\n\n", interface_num);
	char buff[20] = "";
	int ip;
	int if_len = interface_num;
	while (if_len-- > 0)
	{																	 /* 遍历每个接口 */
		printf("%s\n", buf[if_len].ifr_name);							 /* 接口名称 */
		sprintf(net_interface[if_len].name, "%s", buf[if_len].ifr_name); /* 接口名称 */
		printf("-%d-%s--\n", if_len, net_interface[if_len].name);
		/* 获得接口标志 */
		if (!(ioctl(sock_raw_fd, SIOCGIFFLAGS, (char *)&buf[if_len])))
		{
			/* 接口状态 */
			if (buf[if_len].ifr_flags & IFF_UP)
			{
				printf("UP\n");
				net_interface[if_len].flag = 1;
			}
			else
			{
				printf("DOWN\n");
				net_interface[if_len].flag = 0;
			}
		}
		else
		{
			char str[256];
			sprintf(str, "SIOCGIFFLAGS ioctl %s", buf[if_len].ifr_name);
			perror(str);
		}

		/* IP地址 */
		if (!(ioctl(sock_raw_fd, SIOCGIFADDR, (char *)&buf[if_len])))
		{
			printf("IP:%s\n", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
			bzero(buff, sizeof(buff));
			sprintf(buff, "%s", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
			inet_pton(AF_INET, buff, &ip);
			memcpy(net_interface[if_len].ip, &ip, 4);
		}
		else
		{
			char str[256];
			sprintf(str, "SIOCGIFADDR ioctl %s", buf[if_len].ifr_name);
			perror(str);
		}

		/* 子网掩码 */
		if (!(ioctl(sock_raw_fd, SIOCGIFNETMASK, (char *)&buf[if_len])))
		{
			printf("netmask:%s\n", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
			bzero(buff, sizeof(buff));
			sprintf(buff, "%s", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
			inet_pton(AF_INET, buff, &ip);
			memcpy(net_interface[if_len].netmask, &ip, 4);
		}
		else
		{
			char str[256];
			sprintf(str, "SIOCGIFADDR ioctl %s", buf[if_len].ifr_name);
			perror(str);
		}

		/* 广播地址 */
		if (!(ioctl(sock_raw_fd, SIOCGIFBRDADDR, (char *)&buf[if_len])))
		{
			printf("br_ip:%s\n", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
			bzero(buff, sizeof(buff));
			sprintf(buff, "%s", (char *)inet_ntoa(((struct sockaddr_in *)(&buf[if_len].ifr_addr))->sin_addr));
			inet_pton(AF_INET, buff, &ip);
			memcpy(net_interface[if_len].br_ip, &ip, 4);
		}
		else
		{
			char str[256];
			sprintf(str, "SIOCGIFADDR ioctl %s", buf[if_len].ifr_name);
			perror(str);
		}

		/*MAC地址 */
		if (!(ioctl(sock_raw_fd, SIOCGIFHWADDR, (char *)&buf[if_len])))
		{
			printf("MAC:%02x:%02x:%02x:%02x:%02x:%02x\n\n",
				   (unsigned char)buf[if_len].ifr_hwaddr.sa_data[0],
				   (unsigned char)buf[if_len].ifr_hwaddr.sa_data[1],
				   (unsigned char)buf[if_len].ifr_hwaddr.sa_data[2],
				   (unsigned char)buf[if_len].ifr_hwaddr.sa_data[3],
				   (unsigned char)buf[if_len].ifr_hwaddr.sa_data[4],
				   (unsigned char)buf[if_len].ifr_hwaddr.sa_data[5]);
			memcpy(net_interface[if_len].mac, (unsigned char *)buf[if_len].ifr_hwaddr.sa_data, 6);
		}
		else
		{
			char str[256];
			sprintf(str, "SIOCGIFHWADDR ioctl %s", buf[if_len].ifr_name);
			perror(str);
		}
	}					//–while end
	close(sock_raw_fd); //关闭socket
}

int AnalyzeAgreement(char *buf)
{
	mybuf.eth = -1;

	for (int i = 0; i < interface_num; i++)
	{

		if (memcmp(buf, net_interface[i].mac, 6) == 0)
		{
			mybuf.eth = i;

			break;
		}
	}
	if (mybuf.eth == -1)
		return -1;

	memcpy(mybuf.dst_mac, buf, 6);

	memcpy(mybuf.src_mac, buf + 6, 6);

	unsigned short type = 0;
	type = ntohs(*(unsigned short *)(buf + 12));

	//printf("协议类型：type = %#x\n",type);

	if (type == 0x0800)
	{
		unsigned char *ip = buf + 14;

		memcpy(mybuf.src_ip, ip + 12, 4);

		memcpy(mybuf.dst_ip, ip + 16, 4);

		if (buf[14 + 8 + 1] == 0x01)
		{
			unsigned char *icmp = buf + 14 + (ip[0] & 0x0f) * 4;

			mybuf.type = ICMP;
		}
		else if (buf[14 + 8 + 1] == 0x06)
		{
			unsigned char *tcp = buf + 14 + (ip[0] & 0x0f) * 4;

			mybuf.src_port = ntohs(*(unsigned short *)tcp);

			mybuf.dst_port = ntohs(*(unsigned short *)(tcp + 2));

			mybuf.type = TCP;
		}
		else if (buf[14 + 8 + 1] == 0x11)
		{

			unsigned char *udp = buf + 14 + (ip[0] & 0x0f) * 4;

			mybuf.src_port = ntohs(*(unsigned short *)udp);

			mybuf.dst_port = ntohs(*(unsigned short *)(udp + 2));

			mybuf.type = UDP;
		}
		else
		{
			mybuf.type = NuLL;
		}
	}
	else if (type == 0x0806)
	{
		unsigned char *arp = buf + 14;

		memcpy(mybuf.src_ip, arp + 14, 4);

		memcpy(mybuf.dst_ip, arp + 24, 4);

		if (ntohs(*(unsigned short *)(arp + 6)) == 1)
			mybuf.type = ARP_GO;

		if (ntohs(*(unsigned short *)(arp + 6)) == 2)
			mybuf.type = ARP_BACK;
	}
	else if (type == 0x8035)
	{

		unsigned char *rarp = buf + 14;

		memcpy(mybuf.src_ip, rarp + 14, 4);

		memcpy(mybuf.dst_ip, rarp + 24, 4);

		if (ntohs(*(unsigned short *)(rarp + 6)) == 3)
			mybuf.type = RARP_GO;

		if (ntohs(*(unsigned short *)(rarp + 6)) == 4)
			mybuf.type = RARP_BACK;
	}
	else
	{
		mybuf.type = NuLL;
	}
	return mybuf.eth;
}

int SendTo(int len, char *buf, int eth, int fd)
{

	struct sockaddr_ll sll;

	struct ifreq ethreq;

	strncpy(ethreq.ifr_name, net_interface[eth].name, IFNAMSIZ);

	ioctl(fd, SIOCGIFINDEX, &ethreq);

	bzero(&sll, sizeof(sll));

	sll.sll_ifindex = ethreq.ifr_ifindex;

	sendto(fd, buf, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

int IsSameSegment()
{
	//if (mybuf.type == TCP || mybuf.type == UDP || mybuf.type == ICMP)
	{
		for (int i = 0; i < interface_num; i++)
		{
			if (AND(net_interface[i].netmask, net_interface[i].ip) == AND(net_interface[i].netmask, mybuf.dst_ip))
			{

				return i;
			}
		}
	}
	return -1;
}

int AND(unsigned char *first, unsigned char *secend)
{

	unsigned int *first1 = (unsigned char *)first;
	unsigned int *secend1 = (unsigned char *)secend;

	return *first1 & *secend1;
}

//发送ARP包
//目的网卡，选项
//单播，广播，选播
int SendArp(int eth, int flag, int fd, unsigned char *ip)
{
	unsigned char dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	//unsigned char srt_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char msg[1500] = "";
	struct ether_header *eth_hd = (struct ether_header *)msg;
	memcpy(eth_hd->ether_dhost, dst_mac, 6);
	memcpy(eth_hd->ether_shost, net_interface[eth].mac, 6);
	eth_hd->ether_type = htons(0x0806);

	struct arphdr *arp_hd = (struct arphdr *)(msg + 14);
	arp_hd->ar_hrd = htons(1);
	arp_hd->ar_pro = htons(0x0800);
	arp_hd->ar_hln = 6;
	arp_hd->ar_pln = 4;
	arp_hd->ar_op = htons(1);
	memcpy(arp_hd->__ar_sha, net_interface[eth].mac, 6);
	memcpy(arp_hd->__ar_sip, net_interface[eth].ip, 4);
	memcpy(arp_hd->__ar_tha, dst_mac, 6);
	memcpy(arp_hd->__ar_tip, mybuf.dst_ip, 4);

	int len = 42;

	if (flag == 0)
	{
		//单播
		SendTo(len, msg, eth, fd);
	}
	else if (flag == 1)
	{
		for (unsigned int i = BinaryAnd(GetIpNet(eth), 1); i != i | (~((unsigned int)(net_interface[eth].netmask))); i = BinaryAnd(i, 1))
		{
			memcpy(msg + 38, &i, 4);
			SendTo(len, msg, eth, fd);
		}
	}
	else if (flag == 3)
	{
		memcpy(msg + 38, ip, 4);
		SendTo(len, msg, eth, fd) < 0;
	}
	return 0;
}
//获取网络地址(网段地址)
unsigned int GetIpNet(int eth)
{
	unsigned int a = (unsigned int)(net_interface[eth].ip);
	unsigned int b = (unsigned int)(net_interface[eth].netmask);
	return a & b;
}
unsigned int TwoIPNet(unsigned char *first, unsigned char *secend)
{
	unsigned int a = (unsigned int)(first);
	unsigned int b = (unsigned int)(secend);
	return a & b;
}
//两数二进制相加
unsigned int BinaryAnd(unsigned int first, unsigned int second)
{
	unsigned int c;
	while (second != 0)
	{
		c = (first & second) << 1;
		first = first ^ second;
		second = c;
	}
	return first;
}
//ARP处理函数
//返回—1说明没查到
//返回0说明查找成功或删除成功或插入成功
int ArpDispose(unsigned char *ip, unsigned char *mac, unsigned char *mac_back, int flag)
{
	ARPLIST *head = HEAD;

	ARPLIST *temp = (ARPLIST *)malloc(sizeof(ARPLIST));

	if (HEAD == NULL && flag != INSERT)
	{

		return -1;
	}

	while (head != NULL)
	{

		if (memcmp(ip, head->ip, 4) == 0)
		{
			if (flag == DELETE)
			{
				free(temp);

				if (head->front != HEAD)
				{
					head->next->front = head->front;
					head->front->next = head->next;
					free(head);
					return 1;
				}
				else
				{
					HEAD->next = NULL;
					free(head);
					return 1;
				}
			}
			else if (flag == FIND || flag == INSERT)
			{

				memcpy(mac_back, head->mac, 6);
				free(temp);
				return 1;
			}
		}
		if (head->next == NULL)
		{
			break;
		}
		else
		{
			head = head->next;
		}
	}

	if (flag == INSERT)
	{
		memcpy(temp->ip, mybuf.src_ip, 4);
		memcpy(temp->mac, mybuf.src_mac, 6);
		temp->front = NULL;
		temp->next = NULL;
		temp->eth = mybuf.eth;
		InsertArp_listToList(temp, &HEAD);
		return 0;
	}
	return -1;
}

//路由表，吓一跳处理函数
/**********************************
 * 目的IP和链表IP的网络地址对比不同时
 * 返回-1，
 * 如果相同，将节点里面的吓一跳地址与
 * 本机网卡的网段相比较，相同，返回
 * 所出网卡，不相同返回-1
 * 
 * 只能FIND查找和删除
 * 参数：
 * 	unsigned char *ip:查这个IP
 *  unsigned char *mac_back:如果找到，目的mac存放位置
 * 	unsigned char *ip_back:如果找到，目的IP地址
 * 	 int flag：使用选项
 * *******************************/
int Config_Route_MsgDispose(unsigned char *ip, unsigned char *mac_back, unsigned char *ip_back, int flag)
{
	if (Route_Msg == NULL && flag != INSERT)
	{
		return -1;
	}
	int eth = -1;
	CONFIG_ROUTE_MSG *head = Route_Msg;
	
	while (head != NULL)
	{
		//对比路由表中网段地址，与目的网段地址是否相同
		//如果相同，证明路由表中有记录
		// unsigned  int tmp = TwoIPNet(ip, head->Route_Netmask);
		// unsigned int *tm =&tmp;
		// unsigned int tmmp = (unsigned int)(head->Route_Ip);
		
		// printf("%d\n",AND(head->Route_Ip,head->Route_Netmask));
		// printf("%d\n",AND(ip, head->Route_Netmask));
		if (AND(head->Route_Ip,head->Route_Netmask)  == AND(ip, head->Route_Netmask))
		{
			if (flag == DELETE)
			{
				if (head->front != HEAD)
				{
					
					head->next->front = head->front;
					head->front->next = head->next;
					free(head);
					return 0;
				}
				else
				{
					HEAD->next = NULL;
					free(head);
					return 0;
				}
			}
			//如果选项为插入或查找时，需要
			else if (flag == FIND || flag == INSERT)
			{
				for (int i = 0; i < interface_num; i++)
				{
					//判断路由表中的下一跳IP网段为哪一个网卡的网段
					if (AND(head->Route_NextHop, net_interface[i].netmask)==AND(net_interface[i].netmask, net_interface[i].ip))
					{
						if(flag == FIND)
						{
							memcpy(ip_back,head->Route_NextHop,4);
						memcpy(mac_back,net_interface[i].mac,6);
						unsigned char buff[100];
				sprintf(buff,"目的IP：%d,%d,%d,%d",ip_back[0],ip_back[1],ip_back[2],ip_back[3]);
				printf("%s\n",buff);
				printf("所出去的网卡为:%s \n",net_interface[i].name);
						
						}
						eth = i;
					}
					
				}
			}
		}
		
		if (head->next == NULL)
		{

			break;
		}
		else
		{
			head = head->next;
		}
	}
	if (flag == INSERT && eth == -1)
	{
		// memcpy(temp->ip, mybuf.src_ip, 4);
		// memcpy(temp->mac, mybuf.src_mac, 6);
		// temp->front = NULL;
		// temp->next = NULL;
		// temp->eth = mybuf.eth;
		// InsertArp_listToList(temp, &HEAD);
		return 0;
	}
	if (eth == -1)
	{
		//没找到路由表中的下一跳网段的网卡
		//可能写错了路由表
		return -1;
	}
	else
	{
		return eth;
	}
}

// ARPLIST *temp = (ARPLIST *)malloc(sizeof(ARPLIST));
void InsertArp_listToList(ARPLIST *Node, ARPLIST **Head)
{
	if (*Head == NULL)
	{
		*Head = Node;
	}
	else
	{

		ARPLIST *p = *Head;

		while (p->next != NULL)
		{
			p = p->next;
		}

		Node->front = p;
		//将新插入结点的地址保存在最后一个结点的next指针里面
		p->next = Node;
	}
}

void InsertConfig_RouteliToList(CONFIG_ROUTE_MSG *Node, CONFIG_ROUTE_MSG **Head)
{
	Node->front = NULL;
	Node->next = NULL;
	if (*Head == NULL)
	{
		*Head = Node;
	}
	else
	{
		CONFIG_ROUTE_MSG *p = *Head;

		while (p->next != NULL)
		{
			p = p->next;
		}

		Node->front = p;
		//将新插入结点的地址保存在最后一个结点的next指针里面
		p->next = Node;
	}
}

int ReadConfig_Route_MsgFile()
{
	CONFIG_ROUTE_MSG *Route_temp = (CONFIG_ROUTE_MSG *)malloc(sizeof(CONFIG_ROUTE_MSG));
	char text[500] = {0};
	char *FileName = "Config_Route_Msg";
	FILE *fp;
	if ((fp = fopen(FileName, "r")) == NULL)
	{
		perror("fail to fopen");
		return -1;
	}
	while (1)
	{

		if (fgets(text, 500, fp) == NULL)
		{
			break;
		}
		else if (strchr(text, '#') != NULL)
		{
			continue;
		}
		if (strncmp(text, "{", 1) == 0)
		{
			while (1)
			{
				unsigned char buf[4];
				unsigned char buff[100];
				if (fgets(text, 500, fp) == NULL)
				{
					break;
				}

				if (strncmp(text, "Route_Ip", 8) == 0)
				{
					sscanf(text, "%[^:]:%d.%d.%d.%d\n", buff, &buf[0], &buf[1], &buf[2], &buf[3]);
					memcpy(Route_temp->Route_Ip, buf, 4);
				}
				else if (strncmp(text, "Route_Netmask", 13) == 0)
				{
					sscanf(text, "%[^:]:%d.%d.%d.%d\n", buff, &buf[0], &buf[1], &buf[2], &buf[3]);
					memcpy(Route_temp->Route_Netmask, buf, 4);
				}
				else if (strncmp(text, "Route_NextHop", 13) == 0)
				{
					sscanf(text, "%[^:]:%d.%d.%d.%d\n", buff, &buf[0], &buf[1], &buf[2], &buf[3]);
					memcpy(Route_temp->Route_NextHop, buf, 4);
				}
				else if (strchr(text, '#') != NULL)
				{
					continue;
				}
				else
				{
					if (strchr(text, '}') != NULL)
					{
						InsertConfig_RouteliToList(Route_temp, &Route_Msg);
						break;
					}
				}

				for (int i = 0; i < 4; i++)
				{
					printf("%d.", buf[i]);
				}
				printf("\n");
			}
		}
	}
}