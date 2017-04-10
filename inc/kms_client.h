#ifndef KMS_SDK_INCLUDE_CLIENT_H__
#define KMS_SDK_INCLUDE_CLIENT_H__


#include <stdlib.h>      
#include <time.h> 
#include <string>
#include <map>
#include <iostream>
#include "kms_exception.h"
#include "kms_http.h"

using  std::string;
using  std::map;

namespace kms
{

class KMSClient
{
	protected:
		string endpoint;
		string path;
		string secretId;
		string secretKey;
		string method;
		
		KMSHttp http;
		string signMethod;
	public:
		KMSClient();
		
		KMSClient(const string &endpoint, const string &path, const string &secretId, const string &secretKey, const string &method="POST");

		KMSClient& operator=(const KMSClient &r)
		{
			if(this != &r)
			{
				this->endpoint = r.endpoint;
				this->path = r.path;
				this->secretId = r.secretId;
				this->secretKey = r.secretKey;
				this->method = r.method;
				this->signMethod = r.signMethod;
			}
			return *this;
		}

        KMSClient(const KMSClient &r)
        {
           this->endpoint = r.endpoint;
           this->path = r.path;
           this->secretId = r.secretId;
           this->secretKey = r.secretKey;
           this->method = r.method;
           this->signMethod = r.signMethod;
        }
        void setSignMethod (string method)
        {
           if (method != "sha1" && method != "sha256")
            {
                throw  KMSClientException("Only support sha1 or sha256 now");
            }
            else
            {
                this->signMethod = method ;
            }

        }
		void setEndpoint(string endpoint)
		{
			this->endpoint = endpoint;
		}
		void setPath(string path)
		{
			this->path = path;
		}
		
		void setSecretId(string secretId)
		{
			this->secretId = secretId;
		}
		
		void setSecretKey(string secretKey)
		{
			this->secretKey = secretKey;
		}
		
		void setMethod(string method)
		{
			this->method = method;
		}
		
		string call(const string &action, map<string,string> &param);
};

}

#endif

