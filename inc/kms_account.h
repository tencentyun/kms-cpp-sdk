/*
 * @file:kms_account.h
 * @author:yorkxyzhang
 * @description: refer to the kms_account.cpp
 * @date:2017-3-3
 */

#ifndef KMS_SDK_INCLUDE_ACCOUNT_H__
#define KMS_SDK_INCLUDE_ACCOUNT_H__



#include "stdint.h"
#include <utility>
#include <string>
#include <vector>
#include "kms_client.h"



using  std::string;
using  std::pair;
using  std::vector;

namespace kms
{

class KeyMetadata
{
public:
	KeyMetadata():
	KeyId(""),
	CreateTime(-1),
	DeleteTime(-1),
	Description(""),
	KeyState(""),
	KeyUsage(""),
	Alias("")
	{}
	string KeyId;
	int CreateTime;
	int DeleteTime;
	string Description;
	string KeyState;
	string KeyUsage;
	string Alias ;

};

class KMSAccount
{
	public:
		KMSAccount(const string &endpoint,const string &secretId, const string &secretKey, const string &method="POST");
		KMSAccount(const string &endpoint,const string &secretId, const string &secretKey, const string &path, const string &method);
		void create_key(KeyMetadata & meta,const string &Description="",const string & Alias = "" , const string  & KeyUsage="ENCRYPT/DECRYPT");
		void generate_data_key( string &KeyId, const string & KeySpace, int NumberOfBytes,const string & EncryptionContext,string & Plaintext,string &CiphertextBlob);
		string encrypt(const string &KeyId , const string & plaintext, const string & EncryptionContext);
		string decrypt(const string & CiphertextBlob, const string & EncryptionContext);
		void get_key_attributes(const string & KeyId, KeyMetadata & meta);
		void set_key_attributes(const string & KeyId, const string & Alias);
		void enable_key(const string & KeyId);
		void disable_key(const string & KeyId);
		void list_key(vector<string> & keyIds, const int offset= 0 , const int limit = 10);
		void cancel_key_deletion(string keyId );
		void schedule_key_deletion(string keyId, unsigned int pendingWindowInDays );
		void set_sign_method(const string & sign_method="sha1"){this->client.setSignMethod(sign_method);};
	protected:
		KMSClient client;
};

}

#endif

