#ifndef DISSENT_CRYPTO_BLOGDROP_AUTHOR_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_AUTHOR_H_GUARD

#include "BlogDropClient.hpp"
#include "Plaintext.hpp"

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
      explicit BlogDropAuthor(const QSharedPointer<Parameters> params, 
          const QSharedPointer<PublicKeySet> server_pks,
          const QSharedPointer<PrivateKey> author_priv);

      /**
       * Destructor
       */
      virtual ~BlogDropAuthor() {}

      /**
       * Generate a client cover-traffic ciphertext
       * @param out the ciphertext generated
       * @param in the byte array to encode
       * @returns true on success
       */
      bool GenerateAuthorCiphertext(ClientCiphertext &out, const QByteArray &in) const;

      /**
       * Maximum length of a plaintext message
       */
      inline int MaxPlaintextLength() const {
        return Plaintext::CanFit(*GetParameters());
      }

    private:

      QSharedPointer<PrivateKey> _author_priv;
  };
}
}
}

#endif
