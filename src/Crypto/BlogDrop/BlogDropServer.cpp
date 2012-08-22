#include <QtCore>
#include "BlogDropServer.hpp"
#include "CiphertextFactory.hpp"

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

  bool BlogDropServer::AddClientCiphertexts(const QList<QByteArray> &in) 
  {
    if(!in.count()) qWarning() << "Added empty client ciphertext list";

    // list[client_idx]
    QList<QSharedPointer<const ClientCiphertext> > list;

    // Unpack each ciphertext
    for(int client_idx=0; client_idx<in.count(); client_idx++) {
      list.append(CiphertextFactory::CreateClientCiphertext(_params, 
            _server_pk_set, _author_pub, in[client_idx]));
    }

    QSet<int> valid = ClientCiphertext::VerifyProofs(list);

    foreach(int i, valid) {
      _client_ciphertexts.append(list[i]);
    }

    return (valid.count() == in.count());
  }

  QByteArray BlogDropServer::CloseBin() 
  {
    QSharedPointer<ServerCiphertext> s = CiphertextFactory::CreateServerCiphertext(
        _params, _client_ciphertexts);
    s->SetProof(_server_priv);
    return s->GetByteArray();
  }

  bool BlogDropServer::AddServerCiphertext(QSharedPointer<const PublicKey> from, 
      const QByteArray &in) 
  {
    QSharedPointer<const ServerCiphertext> s = CiphertextFactory::CreateServerCiphertext(
        _params, _client_ciphertexts, in);

    if(!s->VerifyProof(from)) return false;
    _server_ciphertexts.append(s);

    return true;
  }

  bool BlogDropServer::RevealPlaintext(QByteArray &out) const
  {
    Plaintext m(_params);
    for(int client_idx=0; client_idx<_client_ciphertexts.count(); client_idx++)
    {
      qDebug() << "client" << client_idx;
      m.Reveal(_client_ciphertexts[client_idx]->GetElements());
    }

    for(int server_idx=0; server_idx<_server_ciphertexts.count(); server_idx++)
    {
      qDebug() << "server" << server_idx;
      m.Reveal(_server_ciphertexts[server_idx]->GetElements());
    }

    return m.Decode(out);
  }

}
}
}
