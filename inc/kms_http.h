#ifndef KMS_SDK_INCLUDE_HTTP_H__
#define KMS_SDK_INCLUDE_HTTP_H__

#include <curl/curl.h>
#include <string>

using std::string;

namespace kms
{
	
class KMSHttp
{	
	public:
		KMSHttp(int timout=5/*sec*/,bool isKeepAlive=true);
		~KMSHttp();
		
		void request(const string &method, const string &url, const string &req, string &rsp);
	
	protected:
		CURL *curl;
		int timeout;
		bool isKeepAlive;
};

}

#endif

