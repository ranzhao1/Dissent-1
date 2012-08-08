#ifndef DISSENT_CRYPTO_BLOGDROP_SERVER_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_SERVER_H_GUARD

#include <QList>
#include <QSharedPointer>

#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "Plaintext.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  class BlogDropServer {

    public:

      /**
       * Constructor: Initialize a BlogDrop client bin
       * @param params Group parameters
       * @param author_pub author public key
       * @param server_priv server private key
       */
      explicit BlogDropServer(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKey> author_pub,
          const QSharedPointer<const PrivateKey> server_priv);

      /**
       * Destructor
       */
      virtual ~BlogDropServer() {}

      /**
       * Remove all ciphertexts from the bin and prepare for the next
       * round
       */
      void ClearBin(); 

      /**
       * Add a client ciphertext and return true if it is valid
       * @param c the ciphertext to add
       */
      bool AddClientCiphertext(QSharedPointer<const ClientCiphertext> c);

      /**
       * Reveal server ciphertext corresponding to added client
       * ciphertexts
       */
      QSharedPointer<ServerCiphertext> CloseBin() const;

      /**
       * Add a server ciphertext and return true if the added 
       * ciphertext is valid
       * @param from public key of the server who sent the ciphertext
       * @param c the server ciphertext to add
       */
      bool AddServerCiphertext(const QSharedPointer<const PublicKey> from, 
          QSharedPointer<const ServerCiphertext> c);

      /**
       * Reveal plaintext for a BlogDrop bin
       * @param out the returned plaintext
       */
      bool RevealPlaintext(QByteArray &out) const; 

      /**
       * Get public key for this server
       */
      inline PublicKey GetPublicKey() const {
        return PublicKey(_server_priv);
      }

    private:

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PublicKey> _author_pub;
      QSharedPointer<const PrivateKey> _server_priv;

      QList<QSharedPointer<const ClientCiphertext> > _client_ciphertexts;
      QList<QSharedPointer<const ServerCiphertext> > _server_ciphertexts;
  };
}
}
}

#endif
