#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "openssl/bn.h"
#include <sys/socket.h>
#include <netinet/in.h>

#define R2 "SkRfNUJIUTRn"

void print_hex(const char *title, const unsigned char *s, int len)
{
    int i;
    printf("%s", title);
    for (i = 0; i < len; ++i)
        printf("%02X", s[i]);
    printf("\n");
}

EC_KEY *get_priv_key(const char* priv_key_file_name)
{
	BIO *bio = BIO_new_file(priv_key_file_name, "rb");
    if (bio == NULL) {
        printf("Error: BIO_new_file failed to open file:%s\n",priv_key_file_name);
		return NULL;
    }
	
	EC_KEY *ec_key = PEM_read_bio_ECPrivateKey(bio,NULL,NULL,NULL);
    if (ec_key == NULL) {
        int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug:d2i_ECPrivateKey_fp failed! error:%s\n",estr ? estr : "NULL");
    }
	printf("leiang debug: get_priv_key ok!\n");
	return ec_key;
}

void get_pubic_key_test(EC_KEY *pubKey)
{
	char x_y[] = "k+EJjaNc/xNOymXas/ugxrO+IqSbbaO2oCrlhhbFiG9TZUiHJUs4cz+vXa8SImMs/n+N7jMXWmyYcKwslPq5rg==";
	unsigned int x_y_l = strlen(x_y);
	char pubkb[1024];
	memset(pubkb,0,sizeof(pubkb));
	
	int pubkbL = base64_decode(x_y,x_y_l,pubkb,sizeof(pubkb));
	printf("pubkbL = %d\n",pubkbL);
	
	BIGNUM* bnx = BN_bin2bn(pubkb,32,NULL);
	BIGNUM* bny = BN_bin2bn(pubkb + 32,32,NULL);
	
	if(EC_KEY_set_public_key_affine_coordinates(pubKey,bnx,bny))
	{
		printf("update public key OK!\n");
		return;
	}
	if(bnx)
		BN_free(bnx);
	if(bny)
		BN_free(bny);
	
	return NULL;
}

EC_KEY *get_pubic_key(const char* public_key_file_name)
{
	BIO *bio = BIO_new_file(public_key_file_name, "rb");
    if (bio == NULL) {
        printf("%s Error: BIO_new_file failed to open file:%s\n",__FUNCTION__,public_key_file_name);
		return NULL;
    }
	//公钥是放在证书中的，还包括其他的内容
	
	X509 *pem = PEM_read_bio_X509(bio,NULL,NULL);
	if (pem == NULL) {
        int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug:PEM_read_bio_X509 failed! error:%s\n",estr ? estr : "NULL");
		return NULL;
    }
	
	//从证书中获取公钥
	EVP_PKEY *evp_key = X509_get_pubkey(pem);
    if (evp_key == NULL) {
        int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug:X509_get_pubkey failed! error:%s\n",estr ? estr : "NULL");
		
		X509_free(pem);
		return NULL;
    }
	
	//将通用的公钥类型转成EC_KEY
	const EC_KEY *ec_key=EVP_PKEY_get0_EC_KEY(evp_key);
	if (ec_key == NULL ) {
        int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		printf("leiang debug:X509_get_pubkey failed! error:%s\n",estr ? estr : "NULL");
		
		EVP_PKEY_free(evp_key);
		X509_free(pem);
		return NULL;
    }
	if(!EC_KEY_is_sm2p256v1(ec_key)) {
		printf("Invalid key type\n");
		EVP_PKEY_free(evp_key);
		X509_free(pem);
		return NULL;
	}
	
	EC_KEY *ret = EC_KEY_dup(ec_key);
	
	EVP_PKEY_free(evp_key);
	X509_free(pem);
	
	printf("leiang debug: get_pubic_key ok!\n");
	return ret;
}

int base64_decode(const char* inbuf,size_t inLen,char *outbuf,size_t outSize)
{
	if(inLen <= 0)
		inLen = strlen(inbuf);
	
	BIO *b64 = BIO_new(BIO_f_base64());
	//实测 这里不设置这个参数会读不到数据，但是设置原数据有没有换行好像没有影响,不是太明白
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(inbuf, inLen);
	
	// 将BIO对象连接起来
    bio = BIO_push(b64, bio);
	printf("src data:%s\n",inbuf);
	printf("len:%d\n",inLen);
	
	// 读取解码后的数据
   
    outSize = BIO_read(bio, outbuf, outSize);
	if(outSize <= 0){
		int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug:BIO_read failed! error:%s\n",estr ? estr : "NULL");
		BIO_free_all(bio);
		return 0;
	}
	BIO_free_all(bio);
	return outSize;
}

int base64_encode(const char* inbuf,size_t inLen,char *outbuf,size_t outSize)
{
	//base64
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, inbuf, inLen);
    BIO_flush(b64);
	
	BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

	printf("bptr->length=%d\n",bptr->length);
	if(bptr->length <= 0)
	{
		printf("bptr->length=%d\n",bptr->length);
		BIO_free_all(b64);
		return 0;
	}	
	
	if(outSize < bptr->length + 1)
	{
		printf("outSize is not enough!\n");
		BIO_free_all(b64);
		return -1;
	}	
	int retlen = bptr->length;
    memcpy(outbuf, bptr->data, bptr->length);
	outbuf[bptr->length] = '\0';

	BIO_free_all(b64);
	return  retlen;
}

int ec_sign_data(EC_KEY *eckey,const char *in,size_t inLen,char *out,size_t outLen)
{
	const EVP_MD *id_md = EVP_sm3();
	const EVP_MD *msg_md = EVP_sm3();
	
	if(!eckey)
		return;
	
	//ID是签名者ID，国密标准里定义的缺省签名者ID用UFT_8字符串表示是“1234567812345678”
	char id[20]="1234567812345678";
	
	//SM2签名及验证过程中，并不是直接计算被签名数据的摘要，而是要经过专门的预处理过程得到摘要。
	
	//先计算摘要
	unsigned char dgst[1024];
	size_t dgstlen = sizeof(dgst);
	// return msg_md( id_md(id, ec_key) || msg )
	if (!SM2_compute_message_digest(id_md, msg_md,
		(const unsigned char *)in, inLen, id, strlen(id),
		dgst, &dgstlen, eckey)) {
		fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
		return;
	}
	
	//对摘要签名
	printf("sm2utl_sign\n");
	char sign[512] = { 0 };
	memset(sign,0,sizeof(sign));
	unsigned int sign_len = sizeof(sign);
	if(SM2_sign(NID_undef,dgst,dgstlen,sign,&sign_len,eckey) == 0)
	{
		int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug:SM2_sign failed! error:%s\n",estr ? estr : "NULL");
		return 0;
	}
	printf("signed len:%d\n",sign_len);
	
	//char signEncode[512];
	int signEncode_len = base64_encode(sign,sign_len,out,outLen);
	if(signEncode_len <= 0)
	{
		printf("leiang debug:base64_encode failed! len:%d\n",signEncode_len);
		return 0;
	}
	printf("signEncode=%s\n",out);
	return signEncode_len;
}

int ec_verify_data(EC_KEY *pubKey,const char *srcData,size_t srcDataLen,char *signedData,size_t signedDataLen)
{
     const EVP_MD *id_md = EVP_sm3();
     const EVP_MD *msg_md = EVP_sm3();

     //ID是签名者ID，国密标准里定义的缺省签名者ID用UFT_8字符串表示是“1234567812345678”
     char id[20]="1234567812345678";

     //SM2签名及验证过程中，并不是直接计算被签名数据的摘要，而是要经过专门的预处理过程得到摘要。

     //先计算摘要
     unsigned char dgst[1024];
     size_t dgstlen = sizeof(dgst);
     // return msg_md( id_md(id, ec_key) || msg )
	if (!SM2_compute_message_digest(id_md, msg_md,
        (const unsigned char *)srcData, srcDataLen, id, strlen(id),
         dgst, &dgstlen, pubKey)) {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        return 0;
    }

    char sign2Decode[1024];
    int ret = base64_decode(signedData, signedDataLen,sign2Decode,sizeof(sign2Decode));
    if(ret <= 0)
    {
		printf("base64_decode failed!\n");
        return 0;
    }
    printf("dgstlen :%d ,sign2Decode len:%d\n",dgstlen,ret);

    ret = SM2_verify(NID_undef, dgst, dgstlen, sign2Decode, ret, pubKey);
    if(ret == 1)
    {
        printf("leiang debug: SM2_verify OK!!!\n");
		return 1;
    }else
    {
        printf("leiang debug: SM2_verify failed!!!\n");
    }
	return 0;
}


int get_server_random1(int socketfd,char *random1)
{
	char recBuf[1024] = {0};
	memset(recBuf,0,sizeof(recBuf));
	
	int recvlen = recvfrom(socketfd,recBuf,sizeof(recBuf),0,NULL,NULL);
	if(recvlen <= 0)
	{
		printf("recvfrom failed:%d\n",errno);
		return 0;
	}
	
	printf("recv:\n%s\n",recBuf);
	
	char *temp = strstr(recBuf,"random1=");
	if(!temp)
	{
		printf("can not find  random1!\n",errno);
		return 0;
	}
	sscanf(temp,"random1=\"%[^\"]",random1);
	printf("random1=%s\n",random1);
	return 1;
}

#define GetStrAttributeValue(str,name)  \
	do{ \
	    memset(name,0,sizeof(name));\
		char *temp = strstr(str,#name"=");\
		if(!temp){ \
			printf("can not find "#name"!\n");\
			return ;\
		}\
		sscanf(temp,#name"=\"%[^\"]",name);\
		printf(#name"=%s len:%d\n",name,strlen(name));\
	}while(0)

int local_sm3(const void *msg,size_t msglen,unsigned char *out,unsigned int *outLen)
{
	EVP_MD_CTX *md_ctx = NULL;
	const EVP_MD *msg_md = EVP_sm3();
	
	if (!(md_ctx = EVP_MD_CTX_new())
		|| !EVP_DigestInit_ex(md_ctx, msg_md, NULL)
		|| !EVP_DigestUpdate(md_ctx, msg, msglen)
		|| !EVP_DigestFinal_ex(md_ctx, out, outLen)) {
		
		printf("sm3 failed!\n");
		if(md_ctx)
			EVP_MD_CTX_free(md_ctx);
		return 0;
	}
	
	EVP_MD_CTX_free(md_ctx);
	return *outLen;
}

unsigned int calculate_msg_nonce(const char *recBuf,const char *method,const char *vkey,char *out,unsigned int outSize)
{
	char from[100];
	char *p = strstr(recBuf,"From: ");
	if(p)
		sscanf(p + 6,"%[^\r\n]",from);
	printf("from=%s\n",from);
	
	char to[100];
	p = strstr(recBuf,"To: ");
	if(p)
		sscanf(p + 4,"%[^\r\n]",to);
	printf("to=%s\n",to);
	
	char callid[100];
	p = strstr(recBuf,"Call-ID: ");
	if(p)
		sscanf(p + 9,"%[^\r\n]",callid);
	printf("callid=%s\n",callid);
	
	char date[100];
	p = strstr(recBuf,"Date: ");
	if(p)
		sscanf(p + 6,"%[^\r\n]",date);
	printf("date=%s\n",date);
	
	char body[200];
	p = strstr(recBuf,"\r\n\r\n");
	if(p)
		strcpy(body, p + 4);
	printf("body=%s\n",body);
	
	char msg[512];
	sprintf(msg,"%s%s%s%s%s%s%s",method,from,to,callid,date,vkey,body);
	
	char sm3msg[512];
	unsigned int sm3msgl = sizeof(sm3msg);
	local_sm3(msg,strlen(msg),sm3msg,&sm3msgl);
	
	if(base64_encode(sm3msg,sm3msgl,out,outSize) <= 0)
	{
		printf("base64_encode failed!\n");
		return 0;
	}
	return outSize;
}

int verify_other_message(int socketfd,const char *vkey)
{
	char *recBuf = (char *)malloc(1024);
	memset(recBuf,0,1024);
	
	int recvlen = recvfrom(socketfd,recBuf,1024,0,NULL,NULL);
	if(recvlen <= 0)
	{
		printf("recvfrom3 failed:%d\n",errno);
		return 0;
	}
#if 1
	printf("recv3:\n%s\n",recBuf);
	
	char nonce[100];
	GetStrAttributeValue(recBuf,nonce);
	
	char method[20];
	sscanf(recBuf,"%s sip:",method);
	printf("method:%s\n",method);
	
	char finl[200];
	memset(finl,0,sizeof(finl));
	calculate_msg_nonce(recBuf,method,vkey,finl,sizeof(finl));
	
	printf("finl  data:%s\n",finl);
	printf("recv nonce:%s\n",nonce);
	
	if(strcmp(finl,nonce) == 0)
	{
		printf("leiang debug:control sip verify OK!\n");
	}else 
		return 0;
	
#endif	
	return 1;
}

const char server_id[] = "34020000002000000075";
const char server_ip[] = "192.168.11.75";
const int server_port = 5060;
	
//const char local_id[] = "34020000001180000001";
const char local_id[] = "34020000001180000002";
const char local_ip[] = "192.168.101.38";
const int local_port = 20000;
	
unsigned int sendMessage(int socketfd,const char* vkey)
{
	char  heartbuff[1024] = "MESSAGE sip:%s@%s:%d SIP/2.0\r\n"
							"Via: SIP/2.0/UDP %s:%d;rport;branch=z9hG4bK377082895\r\n"
							"From: <sip:%s@%s:%d>;tag=231082895\r\n"
							"To: <sip:%s@%s:%d>\r\n"
							"Call-ID: 830082895\r\n"
							"CSeq: 4 MESSAGE\r\n"
							"Content-Type: Application/MANSCDP+xml\r\n"
							"Max-Forwards: 70\r\n"
							"User-Agent: LiveNVR v230519\r\n"
							"Date: %s\r\n"
							"Note: Digest nonce=\"%s\",algorithm=SM3\r\n"
							"Content-Length: %d\r\n\r\n%s";

	char  heartBody[1024] =	"<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
							"<Notify>\r\n"
							"  <CmdType>Keepalive</CmdType>\r\n"
							"  <SN>4</SN>\r\n"
							"  <DeviceID>%s</DeviceID>\r\n"
							"  <Status>OK</Status>\r\n"
							"</Notify>\r\n";

	char timeStr[64] = "2023-06-01T10:37:42";
	get_local_time(timeStr);

	char body[1024];
	memset(body,0,sizeof(body));
	snprintf(body,sizeof(body),heartBody,local_id);
	
	char message[1024];
	memset(message,0,sizeof(message));
	snprintf(message,sizeof(message),heartbuff,server_id,server_ip,server_port,
												local_ip,local_port,
												local_id,local_ip,local_port,
												server_id,server_ip,server_port,
												timeStr,"%s",strlen(body),body);
	
	char nonce[200];
	memset(nonce,0,sizeof(nonce));
	calculate_msg_nonce(message,"MESSAGE",vkey,nonce,sizeof(nonce));
	char final[1024];
	snprintf(final,sizeof(final),message,nonce);
	int sendlen = sendtoAddr(socketfd,final,strlen(final),server_ip,server_port);
	if(sendlen <= 0){
        printf("sendto  Keepalive failed:%d\n",errno);
		return;
	}
	printf("send Keepalive OK:\n%s",final);
	return sendlen;
}

int get_35114_verify(int socketfd)
{
	char recBuf[2048] = {0};
	memset(recBuf,0,sizeof(recBuf));
	
	int recvlen = recvfrom(socketfd,recBuf,sizeof(recBuf),0,NULL,NULL);
	if(recvlen <= 0)
	{
		printf("recvfrom2 failed:%d\n",errno);
		return 0;
	}
	
	printf("recv2:\n%s\n",recBuf);
	
	if(strstr(recBuf,"SIP/2.0 200 OK") == NULL)
		return 0;
	
	char random1[1024];
	char random2[100];
	char deviceid[100];
	char cryptkey[200];
	char sign2[1024];
	
	GetStrAttributeValue(recBuf,random1);
	GetStrAttributeValue(recBuf,random2);
	GetStrAttributeValue(recBuf,deviceid);
	GetStrAttributeValue(recBuf,cryptkey);
	GetStrAttributeValue(recBuf,sign2);
	
	char verifyBuff[1024];
	sprintf(verifyBuff,"%s%s%s%s",random1,random2,deviceid,cryptkey);
	printf("verifyBuff:%s len:%d\n",verifyBuff,strlen(verifyBuff));
	
	
	EC_KEY *pubEck = get_pubic_key("34020000002000000075-sign.cer");
	if(!pubEck)
	{
		printf("get_pubic_key failed！\n");
		return 0;
	}
	//get_pubic_key_test(pubEck);
	
	
	if(!ec_verify_data(pubEck,verifyBuff,strlen(verifyBuff),sign2,strlen(sign2)))
		return 0;
	
	char vkeyDecode[512];
	int vkeyDLen = base64_decode(cryptkey,strlen(cryptkey),vkeyDecode,sizeof(vkeyDecode));
	EC_KEY *peck = get_priv_key("user.key");
		
	char vkey[1024];
	size_t vkey_len = sizeof(vkey);
	if(SM2_decrypt(NID_sm3, (const unsigned char *)vkeyDecode, vkeyDLen, vkey, &vkey_len, peck) != 0)
	{
		vkey[vkey_len] = '\0';
		printf("vkey len:%d,data:%s\n",vkey_len,vkey);
	}
	unsigned int ret = 0;
	
	//ret = verify_other_message(socketfd,vkey);
	
	ret = sendMessage(socketfd,vkey);
	
	while(1)
	{
		recvlen = recvfrom(socketfd,recBuf,sizeof(recBuf),0,NULL,NULL);
		if(recvlen < 0)
		{
			printf("recvfrom2 failed:%d\n",errno);
			return 0;
		}
		recBuf[recvlen] = 0;
		printf("loop recv:%s\n",recBuf);
	}
	
	return ret;
}

void test_35114register()
{
	char buff[1024] = "REGISTER sip:%s@3402000000 SIP/2.0\n"
                      "Via: SIP/2.0/UDP %s:%d;rport;branch=z9hG4bK659022892\n"
                      "From: <sip:%s@%s:%d>;tag=%d\n"
                      "To: <sip:%s@%s:%d>\n"
                      "Call-ID: 621022891\n"
                      "CSeq: %d REGISTER\n"
                      "Contact: <sip:%s@%s:%d>\n"
                      "%s\n"
                      "Max-Forwards: 70\n"
                      "User-Agent: LiveNVR v230519\n"
                      "Expires: 310\n"
                      "Content-Length: 0\r\n\r\n";
	
	char timeStr[64] = "2023-06-01T10:37:42";
	get_local_time(timeStr);
	int tag = 50022892;
	
	char Authorization[1024];
	sprintf(Authorization,"Authorization: Capability algorithm=\"A:SM2;H:SM3;S:SM1/OFB/PKCS5;SI:SM3-SM2\",keyversion=\"%s\"",timeStr);
	
	char register_msg[1024];
	sprintf(register_msg,buff,server_id,
	                          local_ip,local_port,
	                          local_id,local_ip,local_port,tag++,
	                          local_id,local_ip,local_port,
							  1,
	                          local_id,local_ip,local_port,
                              Authorization);
	
	int socketfd = createSocket(local_ip,local_port);
	if(socketfd <= 0)
		return ;
	
	int sendlen = sendtoAddr(socketfd,register_msg,strlen(register_msg),server_ip,server_port);
	if(sendlen <= 0){
        printf("sendto failed:%d\n",errno);
		return;
	}
	
	printf("send:\n%s\n",register_msg);
	
	char random1[256] = { 0 };
	if(!get_server_random1(socketfd,random1))
		return;
	
	char R2_R1_ServiceID[1024];
	sprintf(R2_R1_ServiceID,"%s%s%s",R2,random1,server_id);
	printf("R2_R1_ServiceID:%s\n",R2_R1_ServiceID);
	
	EC_KEY *peck = get_priv_key("user.key");
	char signEncode[1024];
	if(!ec_sign_data(peck,R2_R1_ServiceID,strlen(R2_R1_ServiceID),signEncode,sizeof(signEncode)))
		return ;
	
	
	// printf("leiang debug ec_verify_data test start!!!\n");
	// EC_KEY *myPKey = get_pubic_key("34020000001180000002.cer");
	// if(myPKey)
	// {
		// printf("leiang debug ec_verify_data test %s!!!\n",ec_verify_data(myPKey,R2_R1_ServiceID,strlen(R2_R1_ServiceID),signEncode,strlen(signEncode)) ? "OK":"FAILED");
	// }else
	// {
		// printf("leiang debug get_pubic_key failed!!!\n");
		// printf("leiang debug ec_verify_data test failed!!!\n");
	// }
	
	sprintf(Authorization,"Authorization: Bidirection random1=\"%s\",random2=\"%s\",serverid=\"%s\","
						  "sign1=\"%s\",algorithm=\"A:SM2;H:SM3;S:SM1/OFB/PKCS5;SI:SM3-SM2\"",random1,R2,server_id,signEncode);
	
	
	sprintf(register_msg,buff,server_id,
	                          local_ip,local_port,
	                          local_id,local_ip,local_port,tag++,
	                          local_id,local_ip,local_port,
							  2,
	                          local_id,local_ip,local_port,
                              Authorization);
	
	sendlen = sendtoAddr(socketfd,register_msg,strlen(register_msg),server_ip,server_port);
	if(sendlen <= 0){
        printf("sendto2 failed:%d\n",errno);
		return;
	}
	printf("send2:\n%s\n",register_msg);
	
	if(!get_35114_verify(socketfd))
		return ;
}

int sendtoAddr(int socketfd,const void *buff,size_t len,const char *ip,int port)
{
	struct sockaddr_in remote_addr;
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(port);
	inet_aton(ip, &remote_addr.sin_addr);
	
	return sendto(socketfd,buff,len,0,&remote_addr,sizeof(struct sockaddr_in));
}

int createSocket(const char *ip,int port)
{
	int socketfd = socket(AF_INET,SOCK_DGRAM,0);
	if(socketfd <= 0)
	{
		printf("create socket failed:%d!",errno);
		return -1;
	}
	
	struct sockaddr_in local_addr;
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(port);
	inet_aton(ip, &local_addr.sin_addr);
	
	if(bind(socketfd,(struct sockaddr*)&local_addr,sizeof(struct sockaddr_in)) < 0)
	{
		printf("create socket failed:%d!",errno);
		return -1;
	}
	return socketfd;
}

void get_local_time(char *timeStr)
{
	time_t t = time(NULL);
	struct tm *lt = localtime(&t);
	sprintf(timeStr,"%04d-%02d-%02dT%02d:%02d:%02d",lt->tm_year + 1900,lt->tm_mon + 1,lt->tm_mday,
	lt->tm_hour,lt->tm_min,lt->tm_sec);
}

int main()
{
	// EC_KEY *ec = get_priv_key("user.key");
	// if(ec)
		// printf("leiang debug: get_priv_key ok!\n");
	// char test[100] = "leiang test!";
	// char output[100] = { 0 };
	// printf("src :%s\n",test);
	// base64_encode(test,strlen(test),output,sizeof(output));
	// printf("base64:%s\n",output);
	// char decode[100];
	// memset(decode,0,sizeof(decode));
	// base64_decode(output,strlen(output),decode,sizeof(decode));
	// printf("decode:%s\n",decode);
	
	test_35114register();
	
	return 0;
}

int main1()
{
    const char *msg = "Hello, SM2!";
    const int msg_len = strlen(msg);

    // Generate random SM2 key pair
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_generate_key(key);

    // Get public key and private key
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(key);
    const BIGNUM *priv_key = EC_KEY_get0_private_key(key);

    // Print public key and private key
    unsigned char *pub_key_buf = NULL;
    int pub_key_len = i2o_ECPublicKey((EC_KEY *)key, &pub_key_buf);
    print_hex("Public key: ", pub_key_buf, pub_key_len);
    unsigned char *priv_key_buf = BN_bn2hex(priv_key);
    printf("Private key: %s\n", priv_key_buf);
    OPENSSL_free(pub_key_buf);
    OPENSSL_free(priv_key_buf);

	size_t ciphertext_len = 0;//这里因为传的是指针，一定要定义一样的类型，不然会有可能越界访问

	printf("leiang debug:sizefo(int)= %d ,sizeof(size_t)=%d\n",sizeof(int),sizeof(size_t));
	//GET ciphertext_len
	if(SM2_encrypt(NID_sm3, (const unsigned char *)msg, msg_len, NULL, &ciphertext_len, key) == 0)
	{
		int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug:get ciphertext_len failed! error:%s",estr ? estr : "NULL");
		ciphertext_len = msg_len + 256;
	}
	printf("leiang debug:ciphertext_len need %d\n",ciphertext_len);

    // Encrypt message with SM2
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len);
    if(SM2_encrypt(NID_sm3, (const unsigned char *)msg, msg_len, ciphertext, &ciphertext_len, key) == 0)
	{
		int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug: SM2_encrypt failed! error:%s",estr ? estr : "NULL");
	}
	
    print_hex("Ciphertext: ", ciphertext, ciphertext_len);

	//get plaintext_len
	size_t plaintext_len = 0;
	if(SM2_decrypt(NID_sm3, ciphertext, ciphertext_len, NULL, &plaintext_len, key) == 0)
	{
		int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug:get plaintext_len failed! error:%s\n",estr ? estr : "NULL");
		plaintext_len = msg_len + 256;
	}
    printf("leiang debug:plaintext_len need %d\n",plaintext_len);
	
	// Decrypt ciphertext with SM2
    unsigned char *plaintext = (unsigned char *)malloc(plaintext_len);
    if(SM2_decrypt(NID_sm3, ciphertext, ciphertext_len, plaintext, &plaintext_len, key) == 0)
	{
		int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug: SM2_decrypt failed! error:%s\n",estr ? estr : "NULL");
	}
	
    printf("Plaintext: %s\n", plaintext);
    OPENSSL_free(ciphertext);
    OPENSSL_free(plaintext);

    EC_KEY_free(key);
    ERR_free_strings();
    return 0;
}
