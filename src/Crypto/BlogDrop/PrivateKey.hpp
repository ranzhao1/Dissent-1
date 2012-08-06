#ifndef DISSENT_CRYPTO_BLOGDROP_PRIVATEKEY_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PRIVATEKEY_H_GUARD

#include "Crypto/Integer.hpp"
#include "Parameters.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop private key
   */
  class PrivateKey {

    public:

      /**
       * Constructor: Initialize a random private key
       */
      PrivateKey(const Parameters params);

      /**
       * Destructor
       */
      virtual ~PrivateKey() {}

      /**
       * Return integer exponent
       */
      inline const Integer &GetInteger() const { return _key; }

      /**
       * Return parameters used
       */
      inline const Parameters &GetParameters() const { return _params; }

    private:

      Parameters _params;
      Integer _key;

  };
}
}
}

#endif
