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
       * Get the parameters for this public key 
       */
      Parameters GetParameters() const { return _params; }

      /**
       * Get integer representing the key
       */
      Integer GetInteger() const { return _public_key; }

      /**
       * Equality operator
       * @param other integer to compare
       */
      inline bool operator==(const PublicKey &other) const
      {
        return (_params == other.GetParameters()) && (_public_key == other.GetInteger());
      }

    private:

      const Parameters _params;
      const Integer _public_key;
  };

  inline uint qHash(const PublicKey &key) { 
    return qHash(key.GetInteger().GetByteArray());
  }
}
}
}

#endif
