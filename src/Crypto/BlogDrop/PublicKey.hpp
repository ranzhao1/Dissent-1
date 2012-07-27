#ifndef DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_H_GUARD

#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop public key (g^sk)
   */
  class PublicKey {

    public:

      /**
       * Constructor: Initialize a public key from a private key
       */
      PublicKey(const PrivateKey &key);

      /**
       * Destructor
       */
      virtual ~PublicKey() {}

      /**
       * Get integer representing the key
       */
      const Integer &GetInteger() const { return _public_key; }

    private:

      const Parameters &_params;
      const Integer &_public_key;
  };
}
}
}

#endif
