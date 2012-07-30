#ifndef DISSENT_CRYPTO_BLOGDROP_PLAINTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PLAINTEXT_H_GUARD

#include <QByteArray>
#include "Crypto/Integer.hpp"
#include "Parameters.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop encoded plaintext
   */
  class Plaintext {

    public:

      /**
       * Constructor
       */
      Plaintext(const Parameters &params);

      /**
       * Destructor
       */
      virtual ~Plaintext() {}

      /**
       * Encode ByteArray into BlogDrop plaintext
       * @param QByteArray to encode
       * @returns Parts of bytearray that overflowed
       */
      QByteArray Encode(const QByteArray &input); 

      /**
       * Decode a plaintext element into a QByteArray
       */
      QByteArray Decode() const;

      /**
       * Set plaintext to random value
       */
      void SetRandom();

      /**
       * Return integer representing this plaintext
       */
      inline Integer GetInteger() const { return _m; }

    private:

      const Parameters &_params;
      Integer _m;

  };
}
}
}

#endif
