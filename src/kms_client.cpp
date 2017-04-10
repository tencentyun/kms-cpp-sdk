#include "kms_client.h"
#include "kms_tool.h"
#include "kms_http.h"
#include "kms_exception.h"
#include <algorithm>

using namespace kms;

static const char __version__[] = "KMS SDK VERSION:1.0.0,DATE:" __DATE__;
const char* const CURRENT_VERSION = "SDK_CPP_1.0";

KMSClient::KMSClient()
{
}
		
KMSClient::KMSClient(const string &endpoint, const string &path, const string &secretId, const string &secretKey, const string &method)
{
	this->endpoint = endpoint;
	this->path = path;
	this->secretId = secretId;
	this->secretKey = secretKey;
	this->method = method;
	this->signMethod ="sha1";
}

string KMSClient::call(const string &action, map<string,string> &param)
{
	srand(time(NULL));
	
	param["Action"] = action;
	param["Nonce"] = kms::int2str(rand());
	param["SecretId"] = this->secretId;
	param["Timestamp"] = kms::int2str(time(NULL));
	param["RequestClient"] = CURRENT_VERSION;
	if (this->signMethod =="sha1")
		param["SignatureMethod"] = "HmacSHA1";
	else
	    param["SignatureMethod"] = "HmacSHA256";

	string prefix = this->endpoint.substr(0,5);
	string host="";
	if(prefix=="https")
		host = this->endpoint.substr(8);
	else
		host = this->endpoint.substr(7);
	string src = "";
	src += this->method + host + this->path + "?";
	map<string, string>::iterator it = param.begin();
	bool flag = false;
	for(; it != param.end(); it++)
	{
		if(flag)
			src += "&";
		string s = it->first;
		std::replace(s.begin(),s.end(),'_','.');
		src += s + "=" + it->second;
		flag = true;
	}
	
	param["Signature"] = kms::sign(src, this->secretKey,this->signMethod);
	
	string url = "";
	string req = "";
	string rsp = "";
	if(this->method == "GET")
	{
		url = this->endpoint + this->path + "?";
		map<string, string>::iterator it = param.begin();
		bool flag = false;
		for(; it != param.end(); it++)
		{
			if(flag)
				url += "&";
			url += it->first+ "=" + kms::url_encode(it->second);
			flag = true;
		}
		if(url.length() > 2048)
		{
			throw KMSClientException("URL length is larger than 2K when use GET method");
			return rsp;
		}
	}
	else
	{
		url = this->endpoint + this->path;
		map<string, string>::iterator it = param.begin();
		bool flag = false;
		for(; it != param.end(); it++)
		{
			if(flag)
				req += "&";
			req += it->first+ "=" + kms::url_encode(it->second);
			flag = true;
		}
	}
	http.request(this->method, url, req, rsp);

	return rsp;
}
