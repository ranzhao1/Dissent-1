
#include "BlogDropServer.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropServer::BlogDropServer(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pk_set,
      const QSharedPointer<const PublicKey> author_pub,
      const QSharedPointer<const PrivateKey> server_priv) :
    _params(params),
    _server_pk_set(server_pk_set),
    _author_pub(author_pub),
    _server_priv(server_priv)
  {
  }

  void BlogDropServer::ClearBin()
  {
    _client_ciphertexts.clear();
    _server_ciphertexts.clear();
    _client_pks.clear();
  }

  bool BlogDropServer::AddClientCiphertext(const QList<QSharedPointer<const ClientCiphertext> > &c) 
  {
    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      if(!c[element_idx]->VerifyProof()) return false;
    }
    _client_ciphertexts.append(c);
    return true;
  }

  bool BlogDropServer::AddClientCiphertext(const QByteArray &in) 
  {
    QList<QByteArray> list;
    QList<QSharedPointer<const ClientCiphertext> > ciphers;
    QDataStream stream(in);
    
    stream >> list;

    if(list.count() != _params->GetNElements()) return false;

    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      ciphers.append(QSharedPointer<const ClientCiphertext>(
            new ClientCiphertext(_params, _server_pk_set, _author_pub, list[element_idx])));
    }

    return AddClientCiphertext(ciphers);
  }

  QByteArray BlogDropServer::CloseBin() 
  {
    QList<QByteArray> ciphers;

    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {

      QList<QSharedPointer<const PublicKey> > keys;
      for(int client_idx=0; client_idx<_client_ciphertexts.count(); client_idx++)
      {
        keys.append(_client_ciphertexts[client_idx][element_idx]->GetOneTimeKey());
      }

      _client_pks.append(QSharedPointer<PublicKeySet>(new PublicKeySet(_params, keys)));

      QSharedPointer<ServerCiphertext> s(new ServerCiphertext(_params, _client_pks[element_idx]));
      s->SetProof(_server_priv);
      ciphers.append(s->GetByteArray());
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << ciphers;

    return out;
  }

  bool BlogDropServer::AddServerCiphertext(QSharedPointer<const PublicKey> from, 
      const QList<QSharedPointer<const ServerCiphertext> > &s) 
  {
    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      if(!s[element_idx]->VerifyProof(from)) return false;
    }
    _server_ciphertexts.append(s);

    return true;
  }

  bool BlogDropServer::AddServerCiphertext(QSharedPointer<const PublicKey> from, 
      const QByteArray &in) 
  {
    QList<QByteArray> list;
    QList<QSharedPointer<const ServerCiphertext> > ciphers;
    QDataStream stream(in);
    
    stream >> list;

    if(list.count() != _params->GetNElements()) return false;

    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      ciphers.append(QSharedPointer<const ServerCiphertext>(
            new ServerCiphertext(_params, _client_pks[element_idx], list[element_idx])));
    }

    return AddServerCiphertext(from, ciphers);
  }

  bool BlogDropServer::RevealPlaintext(QByteArray &out) const
  {

    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      QByteArray text;
      Plaintext m(_params);
      for(int client_idx=0; client_idx<_client_ciphertexts.count(); client_idx++)
      {
        m.Reveal(_client_ciphertexts[client_idx][element_idx]->GetElement());
      }

      for(int server_idx=0; server_idx<_server_ciphertexts.count(); server_idx++)
      {
        m.Reveal(_server_ciphertexts[server_idx][element_idx]->GetElement());
      }

      if(!m.Decode(text)) return false;
      out += text;
    }

    return true;
  }

}
}
}
