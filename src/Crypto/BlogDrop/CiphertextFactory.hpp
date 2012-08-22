#ifndef DISSENT_CRYPTO_BLOGDROP_CIPHERTEXT_FACTORY_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CIPHERTEXT_FACTORY_H_GUARD

#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "PublicKey.hpp"
#include "PublicKeySet.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Factory to create ciphertexts
   */
  class CiphertextFactory {

    public:

      typedef Dissent::Crypto::BlogDrop::ClientCiphertext ClientCiphertext;
      typedef Dissent::Crypto::BlogDrop::ServerCiphertext ServerCiphertext;

      static QSharedPointer<ClientCiphertext> CreateClientCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      static QSharedPointer<ClientCiphertext> CreateClientCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub,
          const QByteArray &serialized);

      static QSharedPointer<ServerCiphertext> CreateServerCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QList<QSharedPointer<const ClientCiphertext> > &client_ctexts);

      static QSharedPointer<ServerCiphertext> CreateServerCiphertext(
          const QSharedPointer<const Parameters> params, 
          const QList<QSharedPointer<const ClientCiphertext> > &client_ctexts,
          const QByteArray &serialized);
  };

}
}
}

#endif
