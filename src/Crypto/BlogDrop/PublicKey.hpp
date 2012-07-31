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
       * Initialize and empty public key
       */
      PublicKey();

      /**
       * Constructor: Initialize a public key matching a private key
       */
      PublicKey(const PrivateKey &key);

      /**
       * Initialize an empty public key with these parameters
       */
      PublicKey(const Parameters params, const QByteArray key);

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
       *
       */
      void SetInteger(Integer i) { _public_key = i; }

      /**
       * Get serialized version of the integer
       */
      inline QByteArray GetByteArray() const { return _public_key.GetByteArray(); }

      /**
       * Is the key valid?
       */
      inline bool IsValid() const { return _params.IsElement(_public_key); }

      /**
       * Equality operator
       * @param other integer to compare
       */
      inline bool operator==(const PublicKey &other) const
      {
        return (_params == other.GetParameters()) && (_public_key == other.GetInteger());
      }

    private:

      Parameters _params;
      Integer _public_key;

  };

  inline uint qHash(const PublicKey &key) { 
    return qHash(key.GetInteger().GetByteArray());
  }
}
}
}

#endif
