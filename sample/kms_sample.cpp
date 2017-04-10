/*
 *@file:kms_sample.py
 *@description: kms sample
 *@author:yorkxyzhang
 *@date:2017-3-2
 */
#include<iostream>
#include<vector>
#include<string>
// for kms
#include"kms_common.h"


using namespace std;
using namespace kms;

int main(int argc, char **argv)
{
	  // 从腾讯云官网查询云api密钥信息
      string secretId = "";
      string secretKey = "";
      string endpoint = "";

      KMSAccount account(endpoint,secretId, secretKey);

      try
      {
    	  KeyMetadata meta ;
    	  string Description = "test";
    	  string Alias = "test";
    	  string KeyUsage="ENCRYPT/DECRYPT";
          //create custom key
    	  account.create_key(meta,Description,Alias,KeyUsage);
    	  cout<<"---------------create key success--------------------"<<endl;
    	  cout<<"keyId              "<<meta.KeyId<<endl;
    	  cout<<"CreateTime         "<<kms::int2str(meta.CreateTime)<<endl;
    	  cout<<"Description        "<<meta.Description<<endl;
    	  cout<<"KeyState           "<<meta.KeyState<<endl;
    	  cout<<"KeyUsage           "<<meta.KeyUsage<<endl;
    	  cout<<"Alias              "<<meta.Alias<<endl;

    	  // create a data key
    	  string KeySpec="AES_128";
    	  string Plaintext,CiphertextBlob;
    	  account.generate_data_key(meta.KeyId,KeySpec,1024,"",Plaintext, CiphertextBlob);
    	  cout<<"the data key string is "<<Plaintext<<endl;
    	  cout<<"the encrypted data key string is "<<CiphertextBlob<<endl;

    	  //encrypt the data key
    	  CiphertextBlob = account.encrypt(meta.KeyId,Plaintext,"");
    	  cout<<"the encrypted data is " <<CiphertextBlob<<endl;

    	  //decrypt the encrypted data string
    	  Plaintext = account.decrypt(CiphertextBlob,"");
    	  cout<<"the decrypted data is "<<Plaintext<<endl;

    	  //get key attributes ;
    	  account.get_key_attributes(meta.KeyId,meta);
    	  cout<<"---------------the key meta --------------------"<<endl;
    	  cout<<"keyId              "<<meta.KeyId<<endl;
    	  cout<<"CreateTime         "<<kms::int2str(meta.CreateTime)<<endl;
    	  cout<<"Description        "<<meta.Description<<endl;
    	  cout<<"KeyState           "<<meta.KeyState<<endl;
    	  cout<<"KeyUsage           "<<meta.KeyUsage<<endl;
    	  cout<<"Alias              "<<meta.Alias<<endl;

    	  // set alias
    	  Alias = "For test";
    	  account.set_key_attributes(meta.KeyId, Alias);

          //disable a custom key
    	  account.disable_key(meta.KeyId);
    	  // enable a custom key
    	  account.enable_key(meta.KeyId);

    	  //list keys
    	  vector<string> KeyIds;
    	  account.list_key(KeyIds);
    	  for(unsigned int i = 0 ; i < KeyIds.size(); ++i)
    		  cout<<"the "<<i<<" key id is :"<<KeyIds[i]<<endl;

      }
      catch(KMSServerNetworkException &e)
      {
    	  cout<<"Server Network exception,http status: "<<e.getStatus()<< endl;
    	  return -1;
      }
      catch(KMSServerException &e)
      {
    	  cout<<"Server Action failed,code:"<< e.getCode()<<",message:"<<e.getMessage()<<",requestId:"<<e.getRequestId()<< endl;
    	  return -1;
      }
      catch(KMSClientException &e)
      {
    	  cout<<"KMS Client Exceptrion:"<<e.what()<< endl;
    	  return -2;
      }
      catch(...)
      {
    	  cout<<"unknow error"<<endl;
      }
}

