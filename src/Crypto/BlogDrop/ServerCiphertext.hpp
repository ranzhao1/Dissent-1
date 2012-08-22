#ifndef DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"
#include "ClientCiphertext.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop server ciphertext
   */
  class ServerCiphertext {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param n_elms number of elements per ciphertext
       */
      ServerCiphertext(const QSharedPointer<const Parameters> params, int n_elms);

      /**
       * Destructor
       */
      virtual ~ServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param Server private key used to generate proof
       */
      virtual void SetProof(const QSharedPointer<const PrivateKey> priv) = 0;

      /**
       * Check ciphertext proof
       * @param pub public key of server
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(const QSharedPointer<const PublicKey> pub) const = 0;

      /**
       * Get serialized version
       */
      virtual QByteArray GetByteArray() const = 0;

      virtual inline QList<Element> GetElements() const { return _elements; }

    protected:

      QSharedPointer<const Parameters> _params;
      QList<Element> _elements;
      const int _n_elms;
  };
}
}
}

#endif
