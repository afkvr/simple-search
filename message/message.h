#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <vector>
#include <cstdlib>
#include <assert.h>
#include <string>
#include <cstring>
#include "database/db_interface.h"

namespace bitmile{
namespace msg {

  //message exchange between clients and servers

  enum MessageType {
    BLANK,
    ERROR,
    KEYWORD_QUERY,
    KEYWORD_QUERY_REPLY,
    UPLOAD_DOC,
    UPLOAD_DOC_REPLY,
    DOC_QUERY,
    DOC_QUERY_REPLY,
    SET_ENCRYPT_KEY,
    SET_ENCRYPT_KEY_REPLY
   };

  class Message {

  public:
    inline MessageType Type() { return type_; }
    virtual void Serialize(std::vector<char>& return_data) = 0;

  protected:
    virtual void Deserialize(const char* dat, size_t size) = 0;
    MessageType type_;
  };

  class KeywordQueryMes : public Message {
  public:
    KeywordQueryMes();
    KeywordQueryMes(MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);

    std::vector<std::string> GetKeywords();
    void SetKeywords(std::vector<std::string>& keywords);
  protected:
    void Deserialize(const char* dat, size_t size);

  private:
    std::vector<std::string> keywords_;
  };

  class KeywordQueryReplyMes : public Message {
  public:
    KeywordQueryReplyMes(MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);
    void SetDocuments (std::vector<db::Document>& input_doc);
    std::vector <db::Document> GetDocs ();
  protected:
    void Deserialize(const char* dat, size_t size);
    std::vector<db::Document> docs_;
  };

  class UploadDocMes : public Message {
  public:
    UploadDocMes (MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);

    const db::Document& GetDoc ();
  protected:
    void Deserialize (const char* dat, size_t size);
    db::Document doc_;
  };

  class UploadDocReplyMes : public Message {
  public:
    UploadDocReplyMes (MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);
  protected:
    void Deserialize (const char* dat, size_t size);
    int result_;
    std::string elastic_id_;
  };

  class DocQueryMes : public Message {
  public:
    DocQueryMes (MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);
    std::string GetElasticId();
  protected:
    void Deserialize (const char* data, size_t size);
    std::string elastic_id_;
  };

  class DocQueryReplyMes : public Message {
  public:
    DocQueryReplyMes (MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);
    void SetDoc (const db::Document& document );
    db::Document getDoc() const {return doc_;}
  protected:
    void Deserialize (const char* data, size_t size);
    db::Document doc_;
  };

  class SetEncryptKeyMes : public Message {
  public:
    SetEncryptKeyMes (MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data) {}
  protected:
    void Deserialize (const char* dat, size_t size);
  };

  class SetEncryptKeyReplyMes :public Message {

  };

  class ErrorMes : public Message {
  public:
    ErrorMes (MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);
  protected:
    void Deserialize (const char* dat, size_t size);
  private:
    std::string message;
  };

  class BlankMes : public Message {
  public:
    BlankMes (MessageType type, const char* dat, size_t size);
    void Serialize (std::vector<char>& return_data);
  protected:
    void Deserialize (const char* dat, size_t size) {}
  };

  class MessageFactory {
  public:
    Message* CreateMessage (MessageType type, const char* dat, size_t size);

  protected:
    void Deserialize (const char* dat, size_t size);
  };
} //namespace msg
}//namespace bitmile
#endif
