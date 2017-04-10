#ifndef KMS_SDK_INCLUDE_TOOL_H__
#define KMS_SDK_INCLUDE_TOOL_H__

#include <string>

using std::string;

namespace kms
{	
        typedef unsigned char byte;	

		 string int2str(int n);

		 string url_encode(const string &src);

		 string base64_encode(const byte *src, int length);

		 string base64_decode(std::string const& s);

		 void hmac_sha1(const byte *key, int key_len,const byte *data, int data_len, byte *digest);

		 string sign(const string &src, const string &key,const string & method ="sha1");


}

#endif

