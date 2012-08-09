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
       * @param server_pk_set server public keys
       * @param author_pub author public key
       * @param server_priv server private key
       */
      explicit BlogDropServer(const QSharedPointer<const Parameters> params,  
          const QSharedPointer<const PublicKeySet> server_pk_set,
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
      bool AddClientCiphertext(const QList<QSharedPointer<const ClientCiphertext> > &c);

      /**
       * Add a client ciphertext and return true if it is valid
       * @param in the ciphertext to add
       */
      bool AddClientCiphertext(const QByteArray &in);

      /**
       * Reveal server ciphertext corresponding to added client
       * ciphertexts
       */
      QByteArray CloseBin();

      /**
       * Add a server ciphertext and return true if the added 
       * ciphertext is valid
       * WARNING : You must call CloseBin() before calling this method
       * @param from public key of the server who sent the ciphertext
       * @param c the server ciphertext to add
       */
      bool AddServerCiphertext(const QSharedPointer<const PublicKey> from, 
          const QList<QSharedPointer<const ServerCiphertext> > &c);

      /**
       * Add a server ciphertext and return true if the added 
       * ciphertext is valid
       * WARNING : You must call CloseBin() before calling this method
       * @param from public key of the server who sent the ciphertext
       * @param in the serializd server ciphertext to add
       */
      bool AddServerCiphertext(const QSharedPointer<const PublicKey> from, 
          const QByteArray &in);

      /**
       * Reveal plaintext for a BlogDrop bin
       * @param out the returned plaintext
       */
      bool RevealPlaintext(QByteArray &out) const; 

      /**
       * Get public key for this server
       */
      inline QSharedPointer<const PublicKey> GetPublicKey() const {
        return QSharedPointer<const PublicKey>(new PublicKey(_server_priv));
      }

    private:

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PublicKeySet> _server_pk_set;
      QSharedPointer<const PublicKey> _author_pub;
      QSharedPointer<const PrivateKey> _server_priv;

      /* list[client][element] = ciphertext */
      QList<QList<QSharedPointer<const ClientCiphertext> > > _client_ciphertexts;
      QList<QList<QSharedPointer<const ServerCiphertext> > > _server_ciphertexts;

      /* list[element] = pk_set */
      QList<QSharedPointer<PublicKeySet> > _client_pks;
  };
}
}
}

#endif
