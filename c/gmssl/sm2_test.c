#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "openssl/bn.h"

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
int ec_sign_data(EC_KEY *eckey,const char *in,size_t inLen,char *out,size_t outLen)
{
        const EVP_MD *id_md = EVP_sm3();
        const EVP_MD *msg_md = EVP_sm3();
        //EC_KEY *ec = get_priv_key("user.key");
        //EC_KEY *ec = get_priv_key(pem_key);
        if(!eckey)
                return 0;

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
                return 0;
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
    printf("sign2Decode len:%d\n",ret);

    ret = SM2_verify(NID_undef, dgst, dgstlen, sign2Decode, ret, pubKey);
    if(ret == 1)
    {
        printf("leiang debug: SM2_verify OK!!!\n");
    }else
    {
        printf("leiang debug: SM2_verify failed!!!\n");
    }
	return 0;
}

int ec_decrypt_data(EC_KEY *priKey,const char *srcData,size_t srcDataLen,char *dstData,size_t* dstDataLen)
{
	printf("srcDataLen=%d\n",srcDataLen);
        char vkeyDecode[2048];
	int vkeyDLen = base64_decode(srcData,strlen(srcData),vkeyDecode,sizeof(vkeyDecode));

	printf("base64Decode=%d\n",vkeyDLen);
	
	if(SM2_decrypt(NID_sm3, (const unsigned char *)vkeyDecode, vkeyDLen, dstData, dstDataLen, priKey) == 0)
	{
		int err = ERR_get_error();
		const char *estr = ERR_reason_error_string(err);
		
		printf("leiang debug: SM2_decrypt failed! error:%s\n",estr ? estr : "NULL");
		return 0;
	}
	return *dstDataLen;
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

void decrypt_test(){
	EC_KEY *priKey = get_priv_key("35114/enc.key");
	
	if(!priKey)
		return ;
	
	char srcdata[]="MHkCIQCQZr4KHfuiW5VZe+qeVgWeP0SW0aGPWdSBvTyNOsnvLAIgOBKh4NRueKM71kIkpSbE/V+pcKTytEcOhYWMNwrV4ckEIFbnHrRmxi3OAPBGWRriQ6Rs/OzIlsh54Hw/SbAzLG+fBBDDNxdm4AlAxhI7QYIbLtXA";
	
	char dstData[2048];
	size_t dstDataLen = sizeof(dstData);
	memset(dstData,0,dstDataLen);
	if(ec_decrypt_data(priKey,srcdata,strlen(srcdata),dstData,&dstDataLen) == 0){
		printf("ec_decrypt_data failed!\n");
	}else
	{
		printf("dstData len:%d\n",dstDataLen);
	}
}

int main()
{
	//if()
		decrypt_test();
	char myData[] = "leiangTestSigned";
	size_t myDataLen = strlen(myData);
	
	char signedData[1024] = { 0 };
	size_t signedDataLen = sizeof(signedData);
	
	EC_KEY *priKey = get_priv_key("user.key");
	
	if(!priKey)
		return 0;
	
	printf("leiang debug:start signed:%s\n",myData);
	signedDataLen = ec_sign_data(priKey,myData,myDataLen,signedData,signedDataLen);
	
	EC_KEY *pubKey = get_pubic_key("34020000001180000002.cer");
	if(!pubKey)
		return 0;
	ec_verify_data(pubKey,myData,myDataLen,signedData,signedDataLen);
	
	return 0;
}
