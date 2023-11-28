#include <iostream>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc , char **argv){
    if(argc < 2)
    {
        std::cout << "leiang debug:argc < 2!" << std::endl;
        return 0;
    }

    struct hostent *h = gethostbyname(argv[1]);
    if(!h)
    {
        std::cout << "gethostbyname " << argv[1] << "failed!" << std::endl;
    }
    
    std::cout << "h_length:" << h->h_length << std::endl;
    struct in_addr in;
    int i = 0;
    for( ; h->h_addr_list[i] ; i ++)
    {
        memcpy(&in,h->h_addr_list[i],h->h_length);
        std::cout << "h->h_addr_list[" << i << "]:" << inet_ntoa(in) << std::endl;
    } 
    std::cout << "i = " << i << std::endl;
    return 0;
}
