
#include "BlogDropClient.hpp"
#include "CiphertextFactory.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropClient::BlogDropClient(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PrivateKey> client_priv, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub) :
    _params(params),
    _client_priv(client_priv),
    _server_pks(server_pks),
    _author_pub(author_pub)
  {
  }

  QByteArray BlogDropClient::GenerateCoverCiphertext() const 
  {
    QSharedPointer<ClientCiphertext> c = CiphertextFactory::CreateClientCiphertext(_params, _server_pks, _author_pub);
    c->SetProof(_client_priv);
    return c->GetByteArray();
  }

}
}
}
