#ifndef KMS_SDK_INCLUDE_EXCEPTION_H__
#define KMS_SDK_INCLUDE_EXCEPTION_H__

#include <exception>
#include <string>


using std::exception;
using std::string;

namespace kms
{

class KMSClientException : public exception
{
public:
    KMSClientException(const string &msg) throw()
    {
        this->msg = msg;
    }
	
    virtual ~KMSClientException() throw(){}
	
	virtual const char* what() const throw();
	
	string msg;
};

class KMSServerNetworkException : public exception
{
public:
    KMSServerNetworkException(int status) throw()
    {
        this->status = status;
    }
	
    virtual ~KMSServerNetworkException() throw(){}

    int getStatus() const
    {
        return this->status;
    }
	
	//http status
	int status;
};

class KMSServerException : public exception
{
public:
    KMSServerException(int code, const string &message, const string &requestId) throw()
    {
        this->code = code;
		this->message = message;
		this->requestId = requestId;
    }
	
    ~KMSServerException() throw(){}

    string getRequestId() const
    {
        return this->requestId;
    }
    int getCode() const
    {
        return this->code;
    }
    string getMessage() const
    {
        return this->message;
    }
	

	int code;
	//返回的详细错误信息
	string message;
	//服务器生成的请求Id，便于追踪问题
	string requestId;
};

}

#endif
