#ifndef DISSENT_CRYPTO_BLOGDROP_CLIENT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CLIENT_H_GUARD

#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "Plaintext.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  class BlogDropClient {

    public:

      /**
       * Constructor: Initialize a BlogDrop client bin
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit BlogDropClient(const Parameters params, const PublicKeySet server_pks,
          const PublicKey author_pub);

      /**
       * Destructor
       */
      virtual ~BlogDropClient() {}


      /**
       * Generate a client cover-traffic ciphertext
       */
      ClientCiphertext GenerateCoverCiphertext() const;

    protected: 

      inline Parameters GetParameters() const { return _params; }
      inline PublicKeySet GetServerKeys() const { return _server_pks; }
      inline PublicKey GetAuthorKey() const { return _author_pub; }

    private:

      Parameters _params;
      PublicKeySet _server_pks;
      PublicKey _author_pub;
  };
}
}
}

#endif
