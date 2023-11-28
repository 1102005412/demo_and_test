#include <thread>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <arpa/inet.h>

using namespace std;

static bool exitThread = false;
int sendThead(int socket)
{
	string buff = "leiang test\n";
	int ret = 0;
	while(!exitThread)
	{
		ret = send(socket,buff.c_str(),buff.size(),0);
		if(ret == -1)
		{
			printf("leiang debug:send error:%d,%s\n",errno,strerror(errno));
		}
		sleep(1);
	}
	return 0;
}

int main(int argc,char **argv)
{
	
	int	m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	string mRemoteIp="192.168.101.38";
	
	int mRemotePort = 5888;
	string mLocalIp = "192.168.101.38";
	
	//连接不上UDP的原因，之前写死连接的是TCP
	//m_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (m_socket == -1) {
		printf("[%s][TCP] socket create error : %s\n", __FUNCTION__, strerror(errno));
		return 0;
	}

	sockaddr_in serAddr;
	memset((void *)&serAddr, 0x00, sizeof(serAddr));
	serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(mRemotePort);
	inet_pton(AF_INET, mRemoteIp.c_str(), (void *)&serAddr.sin_addr);


	sockaddr_in localAddr;
	memset((void *)&localAddr, 0x00, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = 0;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (mLocalIp.size() > 0)
		inet_pton(AF_INET, mLocalIp.c_str(), (void *)&localAddr.sin_addr);

	int flag = 1;
	int ret = setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
	if (ret == -1) {
		printf("[%s][TCP] socket set option reusable error : %s", __FUNCTION__, strerror(errno));
		return 0;
	}

	ret = ::bind(m_socket, (sockaddr *)&localAddr, sizeof(localAddr));
	if (ret == -1) {
		printf("[%s][TCP] socket bind error : %s", __FUNCTION__, strerror(errno));
		return 0;
	}

	ret = connect(m_socket, (sockaddr *)&serAddr, sizeof(serAddr));
	//修改一下
	//if (ret == -1)
	if (ret !=0)
	{
		printf("[%s][TCP] socket connect error : %s", __FUNCTION__, strerror(errno));
		return 0;
	}
	
	std::thread sendt(sendThead,m_socket);
	sleep(5);
	close(m_socket);
	sleep(5);
	exitThread = true;
	sendt.join();
	return 0;
}
