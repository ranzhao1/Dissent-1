#ifndef DISSENT_CRYPTO_BLOGDROP_AUTHOR_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_AUTHOR_H_GUARD

#include "BlogDropClient.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  class BlogDropAuthor : public BlogDropClient {

    public:

      /**
       * Constructor: Initialize a BlogDrop author bin
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit BlogDropAuthor(const Parameters params, const PublicKeySet server_pks,
          const PrivateKey author_priv);

      /**
       * Destructor
       */
      virtual ~BlogDropAuthor() {}


      /**
       * Generate a client cover-traffic ciphertext
       */
      ClientCiphertext GenerateAuthorCiphertext(const QByteArray &in, QByteArray &out) const;

    private:

      PrivateKey _author_priv;
  };
}
}
}

#endif
