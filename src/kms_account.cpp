

/*
 * @file   kms_account.cpp
 * @author: yorkxyzhang
 * @description: kms account class and it provides all interfaces for the client.
 *               tips: kms account class is not multithreading safety.
 * @date:2017-3-3
 */
#include <utility>
#include <vector>
#include "kms_account.h"
#include "kms_exception.h"
#include "json/json.h"
#include "kms_tool.h"

#include <sstream>
using namespace kms;
using std::pair;
using std::map;
using std::stringstream;
using std::string;
using std::vector;
namespace kms {

    /*
     * KMSAccount
     * @endpoint    kms endpoint
     * @secretId    account secretId
     * @secretKey   account secretKey
     * @method      https method default :POST
     */
	KMSAccount::KMSAccount(const string &endpoint, const string &secretId, const string &secretKey, const string &method)
		:client(endpoint, "/v2/index.php", secretId, secretKey, method)
	{
	}
	/*
	 * KMSAccount
	 * @endpoint    kms endpoint
	 * @secretId    account secretId
	 * @secretKey   account secretKey
	 * @method      https method default :POST
	 */
	KMSAccount::KMSAccount(const string &endpoint, const string &secretId, const string &secretKey, const string &path, const string &method)
		: client(endpoint, path, secretId, secretKey, method)
	{
	}
    /*
     * create_key   create qcloud master key
     * @meta        the meta is the custom master key metadata if create success. refer to the KeyMeta class
     * @Description key description
     * @Alias       key alias name.
     * @KeyUsage:   the usage of the key default 'ENCRYPT/DECRYPT'
     * return       void
     */
	void KMSAccount::create_key(KeyMetadata & meta,const string &Description,const string & Alias  , const string  & KeyUsage)
	{
		map<string , string> param;
		if (Description.size() > 0)
		    param["description"] = Description;
		param["alias"] = Alias;
		if(KeyUsage.size() > 0)
		    param["keyUsage"] = KeyUsage;
		string result = this->client.call("CreateKey",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
                    throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
			throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());
		Json::Value MetaValue = value["keyMetadata"];
		meta.KeyId = MetaValue["keyId"].asString();
		meta.Alias = MetaValue["alias"].asString();
		meta.CreateTime = MetaValue["createTime"].asInt();
		meta.Description = MetaValue["description"].asString();
		meta.KeyState = MetaValue["keyState"].asString();
		meta.KeyUsage = MetaValue["keyUsage"].asString();
	}
    /*
     * generate_data_key   generate_data_key by the custom master key
     * @KeyId              the custom master key id
     * @KeySpec            AES_128 or AES_256
     * @NumberOfBytes      the size of the data key 1-1024B
     * @EncryptionContext  the json string context
     * @Plaintext          the data key string
     * @CiphertextBlob     the encrypted data key string
     * return void
     */
	void KMSAccount::generate_data_key(string &KeyId, const string & KeySpec, int NumberOfBytes,const string & EncryptionContext,string & Plaintext,string &CiphertextBlob)
	{
		map<string , string> param;
		if(KeySpec.size() > 0)
		    param["keySpec"] = KeySpec;
		param["keyId"] = KeyId;
		if(NumberOfBytes > 0)
		    param["numberOfBytes"] =  kms::int2str(NumberOfBytes);
		if(EncryptionContext.size() > 0 )
    		param["encryptionContext"] = EncryptionContext;

		string result = this->client.call("GenerateDataKey",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
			if (code != 0)
			throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());

		KeyId = value["keyId"].asString();
		Plaintext = kms::base64_decode(value["plaintext"].asString());
	    CiphertextBlob  = value["ciphertextBlob"].asString();


	}
    /*
     * encrypt             encrypt plaintext
     * @keyid              the custom key id
     * @plaintext          the data string
     * @EncryptionContext  the json string context if you provide it here , you must provide the same when decrypt the data
     * return              the data string encryped
     */
	string KMSAccount::encrypt(const string & keyId, const string & plaintext, const std::string & EncryptionContext)
	{
		map<string ,string >param;
		if (keyId.size() > 0)
		    param["keyId"] = keyId;
		if (plaintext.size() > 0 & plaintext.size() < 4096)
		    param["plaintext"] = kms::base64_encode(reinterpret_cast<const unsigned char *>(plaintext.c_str()),plaintext.length());
		if (EncryptionContext.size() > 0)
		param["encryptionContext"] = EncryptionContext;
		string result = this->client.call("Encrypt",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
		    throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());
		return value["ciphertextBlob"].asString();



	}
	/*
	 * decrypt               decrypt the data string
	 * @CiphertextBlob       the encryped data string
	 * @EncryptionContext    the json string context
	 * return                the data string
	 */
	string KMSAccount::decrypt( const string & CiphertextBlob, const string & EncryptionContext)
	{
		map<string ,string> param;
		if (CiphertextBlob.size() > 0 and CiphertextBlob.size() < 4096)
		    param["ciphertextBlob"] = CiphertextBlob;
		if (EncryptionContext.size() > 0)
		    param["encryptionContext"] = EncryptionContext;
		string result = this->client.call("Decrypt",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
			throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());
        return kms::base64_decode(value["plaintext"].asString());

	}
	/*
	 * get_key_attributes get the custom key meta
	 * @keyid             the custom key id
	 * @meta              the key meta
	 * return             void
	 */
	void KMSAccount::get_key_attributes(const string & KeyId, KeyMetadata & meta)
	{
		map<string ,string > param ;
		if (KeyId.size() > 0)
	        param["keyId"] = KeyId;

		string result = this->client.call("GetKeyAttributes",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
		    throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());
		Json::Value MetaValue = value["keyMetadata"];
		meta.KeyId = MetaValue["keyId"].asString();
		meta.Alias = MetaValue["alias"].asString();
		meta.CreateTime = MetaValue["createTime"].asInt();
		meta.Description = MetaValue["description"].asString();
		meta.KeyState = MetaValue["keyState"].asString();
		meta.KeyUsage = MetaValue["keyUsage"].asString();

	}
	/*
	 * set_key_attributes  set key attributes only support setting alias
	 * @keyid              the custom key id
	 * @Alias              the alias
	 * return              void
	 */
	void KMSAccount::set_key_attributes(const string & KeyId, const string & Alias)
	{
		map<string ,string> param;
		if (KeyId.size() > 0)
		    param["keyId"] = KeyId;
		if (Alias.size() > 0)
		    param["alias"] = Alias;
		string result = this->client.call("SetKeyAttributes",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
			throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());


	}
	/*
	 * enable_key          enable the custom key
	 * @KeyId              the custom key id
	 * return              void
	 */
	void KMSAccount::enable_key(const string & KeyId)
	{
		map<string ,string> param;
		if (KeyId.size() > 0 )
		param["keyId"] = KeyId;
		string result = this->client.call("EnableKey",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
			throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());

	}
	/*
	 * disable_key           disable the custom key
	 * @KeyId                the custom key id
	 * return                void
	 */
	void KMSAccount::disable_key(const string & KeyId)
	{
		map<string ,string> param;
		if(KeyId.size() > 0)
		    param["keyId"] = KeyId;
		string result = this->client.call("DisableKey",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
			throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());


	}
	/*
	 * list_key           list the custom key
	 * @offset            default = 0
	 * @limit             default = 10
	 * return             void
	 */
	void KMSAccount::list_key(vector<string> & keyIds,const int offset , const int limit )
	{
		map<string ,string > param;
		if(offset > 0)
		    param["offset"] = kms::int2str(offset);
		if (limit > 0 )
		    param["limit"] = kms::int2str(limit);
		string result = this->client.call("ListKey",param);
		Json::Reader reader ;
		Json::Value value ;
		if (!reader.parse(result, value))
			throw KMSClientException("Json parse failed");
		int code = value["code"].asInt();
		if (code != 0)
			throw KMSServerException(code, value["message"].asString(), value["requestId"].asString());
		Json::Value valueKeys = value["keys"];
		for(unsigned int i = 0 ; i< valueKeys.size(); ++i)
			keyIds.push_back(valueKeys[i]["keyId"].asString());
	}


}
