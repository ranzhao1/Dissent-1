
#include "BlogDropClient.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropClient::BlogDropClient(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub)
  {
  }

  QByteArray BlogDropClient::GenerateCoverCiphertext() const 
  {
    QSharedPointer<ClientCiphertext> c(new ClientCiphertext(_params, _server_pks, _author_pub));
    c->SetProof();
    return c->GetByteArray();
  }

}
}
}
