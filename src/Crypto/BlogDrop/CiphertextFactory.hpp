#ifndef DISSENT_CRYPTO_BLOGDROP_CIPHERTEXT_FACTORY_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CIPHERTEXT_FACTORY_H_GUARD

#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "PublicKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Factory to create ciphertexts
   */
  class CiphertextFactory {

    public:

      static QSharedPointer<Dissent::Crypto::BlogDrop::ClientCiphertext> CreateClientCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      static QSharedPointer<Dissent::Crypto::BlogDrop::ClientCiphertext> CreateClientCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub,
          const QByteArray &serialized);

  };

}
}
}

#endif
