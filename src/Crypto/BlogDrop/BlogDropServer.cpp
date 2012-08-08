
#include "BlogDropServer.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropServer::BlogDropServer(const QSharedPointer<Parameters> params, 
      const QSharedPointer<PublicKey> author_pub,
      const QSharedPointer<PrivateKey> server_priv) :
    _params(params),
    _author_pub(author_pub),
    _server_priv(server_priv)
  {
  }

  void BlogDropServer::ClearBin()
  {
    _client_ciphertexts.clear();
    _server_ciphertexts.clear();
  }

  bool BlogDropServer::AddClientCiphertext(ClientCiphertext c) 
  {
    if(!c.VerifyProof()) return false;
    _client_ciphertexts.append(c);
    return true;
  }

  ServerCiphertext BlogDropServer::CloseBin() const
  {
    QList<PublicKey> keys;
    for(int i=0; i<_client_ciphertexts.count(); i++)
    {
      keys.append(_client_ciphertexts[i].GetOneTimeKey());
    }

    PublicKeySet client_pks(*_params, keys);

    ServerCiphertext s(*_params, client_pks);
    s.SetProof(*_server_priv);
    return s;
  }

  bool BlogDropServer::AddServerCiphertext(const QSharedPointer<PublicKey> from, ServerCiphertext s) 
  {
    if(!s.VerifyProof(*from)) return false;
    _server_ciphertexts.append(s);
    return true;
  }

  bool BlogDropServer::RevealPlaintext(QByteArray &out) const
  {
    Plaintext m(*_params);
    for(int client_idx=0; client_idx<_client_ciphertexts.count(); client_idx++)
    {
      m.Reveal(_client_ciphertexts[client_idx].GetElement());
    }

    for(int server_idx=0; server_idx<_server_ciphertexts.count(); server_idx++)
    {
      m.Reveal(_server_ciphertexts[server_idx].GetElement());
    }

    return m.Decode(out);
  }

}
}
}
