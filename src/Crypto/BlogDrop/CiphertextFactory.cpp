
#include "CiphertextFactory.hpp"
#include "ElGamalClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<ClientCiphertext> CreateClientCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub)
  {
    return QSharedPointer<ClientCiphertext>(new ElGamalClientCiphertext(
          params, server_pks, author_pub));
  }
 
  QSharedPointer<ClientCiphertext> CreateClientCiphertext(
      const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized)
  {
    return QSharedPointer<ClientCiphertext>(new ElGamalClientCiphertext(
          params, server_pks, author_pub, serialized));
  }

}
}
}
