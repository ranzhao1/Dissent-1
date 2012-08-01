#ifndef DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_SET_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_SET_H_GUARD

#include <QList>

#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "PublicKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding a collection of public keys. 
   * This object does some preprocessing on the keys to 
   * speed up ciphertext operations.
   */
  class PublicKeySet {

    public:

      /**
       * Constructor: Initialize using a QSet of keys
       * @params params group parameters
       * @params keys keyset to use
       */
      PublicKeySet(const Parameters params, const QList<PublicKey> &keys);

      /**
       * Destructor
       */
      virtual ~PublicKeySet() {}

      /**
       * Get integer representing the keyset
       */
      const Integer GetInteger() const { return _key; }

    private:

      Parameters _params;

      /**
       * Product of all public keys:
       *   key = (g^x0)(g^x1)...(g^xN)
       */
      Integer _key;
  };
}
}
}

#endif
