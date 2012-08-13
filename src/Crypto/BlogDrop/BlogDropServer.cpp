#include <QtCore>
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

  void BlogDropServer::UnpackClientCiphertext(const QByteArray &in,
          QList<QSharedPointer<const ClientCiphertext> > &out) const
  {
    QList<QByteArray> list;

    QDataStream stream(in);
    stream >> list;

    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      out.append(QSharedPointer<const ClientCiphertext>(
            new ClientCiphertext(_params, _server_pk_set, _author_pub, list[element_idx])));
    }
  }

  void BlogDropServer::AddClientCiphertexts(const QList<QByteArray> &in) 
  {
    if(!in.count()) qWarning() << "Added empty client ciphertext list";

    // list_of_lists[client_idx][element_idx]
    QList<QList<QSharedPointer<const ClientCiphertext> > > list_of_lists;

    // Unpack each ciphertext
    for(int client_idx=0; client_idx<in.count(); client_idx++) {
      QList<QSharedPointer<const ClientCiphertext> > l;
      UnpackClientCiphertext(in[client_idx], l);
      if(l.count() != _params->GetNElements()) {
        qWarning() << "Skipping ciphertext with incorrect length";
        continue;
      }
      list_of_lists.append(l);
    }

    CryptoFactory::ThreadingType t = CryptoFactory::GetInstance().GetThreadingType(); 
    if(t == CryptoFactory::MultiThreaded) {
      
      QList<QList<QSharedPointer<const ClientCiphertext> > > valid = QtConcurrent::blockingFiltered(list_of_lists, 
          &ClientCiphertext::VerifyProofs);  

      if(valid.count() != list_of_lists.count())
          qWarning() << "Skipping invalid ciphertexts";
      _client_ciphertexts += valid;
      
    } else if(t == CryptoFactory::SingleThreaded) {
      // Verify each set of ciphertexts
      for(int client_idx=0; client_idx<list_of_lists.count(); client_idx++) {
        const bool ret = ClientCiphertext::VerifyProofs(list_of_lists[client_idx]);
        if(ret) _client_ciphertexts.append(list_of_lists[client_idx]);
        else {
          qWarning() << "Skipping invalid ciphertext";
        }
      }
    } else {
      qFatal("Unknown threading type");
    }
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

    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      if(!ciphers[element_idx]->VerifyProof(from)) return false;
    }
    _server_ciphertexts.append(ciphers);

    return true;
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
