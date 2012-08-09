
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

  bool BlogDropServer::AddClientCiphertext(QSharedPointer<const ClientCiphertext> c) 
  {
    if(!c->VerifyProof()) return false;
    _client_ciphertexts.append(c);
    return true;
  }

  bool BlogDropServer::AddClientCiphertext(const QByteArray &in) 
  {
    QSharedPointer<ClientCiphertext> c(new ClientCiphertext(_params, _server_pk_set, _author_pub, in));
    return AddClientCiphertext(c);
  }

  QSharedPointer<ServerCiphertext> BlogDropServer::CloseBin() 
  {
    QList<QSharedPointer<const PublicKey> > keys;
    for(int i=0; i<_client_ciphertexts.count(); i++)
    {
      keys.append(_client_ciphertexts[i]->GetOneTimeKey());
    }

    _client_pks = QSharedPointer<PublicKeySet>(new PublicKeySet(_params, keys));

    QSharedPointer<ServerCiphertext> s(new ServerCiphertext(_params, _client_pks));
    s->SetProof(_server_priv);
    return s;
  }

  bool BlogDropServer::AddServerCiphertext(QSharedPointer<const PublicKey> from, 
      QSharedPointer<const ServerCiphertext> s) 
  {
    if(!s->VerifyProof(from)) return false;
    _server_ciphertexts.append(s);
    return true;
  }

  bool BlogDropServer::AddServerCiphertext(QSharedPointer<const PublicKey> from, 
      const QByteArray &in) 
  {
    QSharedPointer<ServerCiphertext> s(new ServerCiphertext(_params, _client_pks, in));
    return AddServerCiphertext(from, s);
  }

  bool BlogDropServer::RevealPlaintext(QByteArray &out) const
  {
    Plaintext m(_params);
    for(int client_idx=0; client_idx<_client_ciphertexts.count(); client_idx++)
    {
      m.Reveal(_client_ciphertexts[client_idx]->GetElement());
    }

    for(int server_idx=0; server_idx<_server_ciphertexts.count(); server_idx++)
    {
      m.Reveal(_server_ciphertexts[server_idx]->GetElement());
    }

    return m.Decode(out);
  }

}
}
}
