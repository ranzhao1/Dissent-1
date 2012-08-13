#ifndef DISSENT_CRYPTO_BLOGDROP_PLAINTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PLAINTEXT_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
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

      /** * Constructor
       */
      Plaintext(const QSharedPointer<const Parameters> params);

      /**
       * Destructor
       */
      virtual ~Plaintext() {}

      /**
       * Encode ByteArray into BlogDrop plaintext
       * @param input QByteArray to encode
       * @returns Parts of bytearray that overflowed
       */
      QByteArray Encode(const QByteArray &input); 

      /**
       * Decode a plaintext element into a QByteArray
       * @param ret reference in which to return string
       * @returns true if everything is okay, false if cannot read
       *          string
       */
      bool Decode(QByteArray &ret) const;

      /**
       * Set plaintext to random value
       */
      void SetRandom();

      /**
       * Return integer representing this plaintext
       */
      inline Integer GetInteger() const { return _m; }

      /**
       * Number of bytes that can fit in a plaintext
       */
      inline static int CanFit(const QSharedPointer<const Parameters> params) {
        return params->GetQ().GetByteCount() - 4;
      }

      /**
       * Reveal a plaintext by combining ciphertext elements
       */
      void Reveal(const Integer &c);

    private:

      const QSharedPointer<const Parameters> _params;
      Integer _m;

  };

}
}
}

#endif
