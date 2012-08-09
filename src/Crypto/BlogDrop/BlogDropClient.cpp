
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
    QList<QByteArray> list;
    for(int element_idx=0; element_idx<_params->GetNElements(); element_idx++) {
      QSharedPointer<ClientCiphertext> c(new ClientCiphertext(_params, _server_pks, _author_pub));
      c->SetProof();
      list.append(c->GetByteArray());
    }
 
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }

}
}
}
