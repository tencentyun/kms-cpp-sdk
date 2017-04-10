
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <string>
#include <sstream>
#include "kms_tool.h"

using  std::string;
using  std::stringstream;


namespace kms
{

	string int2str(int n)
	{
		stringstream ss;
		ss << n;
		return ss.str();
	}

	static inline bool is_base64(unsigned char c) {
	  return (isalnum(c) || (c == '+') || (c == '/'));
	}

	string url_encode(const string &src)
	{
		static const char *hex = "0123456789ABCDEF";

		string dst;
		for (size_t i = 0; i < src.size(); i++)
		{
			byte c = (byte)src[i];
			if (isalnum(c) || (c == '-') || (c == '_') || (c == '.') || (c == '!') ||
				(c == '~') || (c == '*') || (c == '\'') || (c == '(') ||
				(c == ')') || (c == '/'))
			{
				dst += c;
			}
			else if (c == ' ')
			{
				dst += "%20";
			}
			else
			{
				dst += '%';
				dst += hex[c >> 4];
				dst += hex[c & 15];
			}
		}

		return dst;
	}

	string base64_encode(const byte *src, int length)
	{
		static const char *b64c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		string dst;
		const byte *p = src;

		while (length)
		{
			dst += b64c[*p >> 2];
			if (!--length)
			{
				dst += b64c[(*p & 0x3) << 4];
				dst += "==";
				break;
			}
			dst += b64c[((*p & 0x3) << 4) | (*(p + 1) >> 4)];
			p++;
			if (!--length)
			{
				dst += b64c[(*p & 0xF) << 2];
				dst += '=';
				break;
			}
			dst += b64c[((*p & 0xF) << 2) | (*(p + 1) >> 6)];
			p++;

			dst += b64c[*p & 0x3F];
			p++, length--;
		}

		return dst;
	}
    /*
     * base64 decode
     */
	std::string base64_decode(std::string const& encoded_string) {
	static const std::string base64_chars ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	  int in_len = encoded_string.size();
	  int i = 0;
	  int j = 0;
	  int in_ = 0;
	  unsigned char char_array_4[4], char_array_3[3];
	  std::string ret;

	  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
	    char_array_4[i++] = encoded_string[in_]; in_++;
	    if (i ==4) {
	      for (i = 0; i <4; i++)
	        char_array_4[i] = base64_chars.find(char_array_4[i]);

	      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
	      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
	      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

	      for (i = 0; (i < 3); i++)
	        ret += char_array_3[i];
	      i = 0;
	    }
	  }

	  if (i) {
	    for (j = i; j <4; j++)
	      char_array_4[j] = 0;

	    for (j = 0; j <4; j++)
	      char_array_4[j] = base64_chars.find(char_array_4[j]);

	    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
	    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
	    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

	    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
	  }

	  return ret;
	}

    string sign(const string &src, const string &key,const string &method)
	{
			unsigned char result[32];
			unsigned int len=0;
			HMAC_CTX ctx;
			HMAC_CTX_init(&ctx);

			if(method  == "sha256")
			{
				HMAC_Init_ex(&ctx,key.c_str(),key.size(),EVP_sha256(),NULL);
				len=32;
			}
			else
			{
				HMAC_Init_ex(&ctx,key.c_str(),key.size(),EVP_sha1(),NULL);
				len=20;
			}
			HMAC_Update(&ctx, (unsigned char*)src.c_str(), src.size());
			HMAC_Final(&ctx, result, &len);
			HMAC_CTX_cleanup(&ctx);

			return kms::base64_encode(result,len);
	}

}
