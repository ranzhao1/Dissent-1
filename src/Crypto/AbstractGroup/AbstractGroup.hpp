#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ABSTRACT_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ABSTRACT_GROUP_H_GUARD

#include "Crypto/Integer.hpp"
#include "Element.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class AbstractGroup {

    public:

      AbstractGroup() {}

      virtual ~AbstractGroup() {}

      virtual Element Multiply(const Element &a, const Element &b) const = 0;

      virtual Element Exponentiate(const Element &a, const Integer &exp) const = 0;

      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const = 0;

      virtual Element Inverse(const Element &a) const = 0;

      virtual QByteArray ElementToByteArray(const Element &a) const = 0;

      virtual Element ElementFromByteArray(const QByteArray &bytes) const = 0;

      /**
       * Return true if a is an element of the group
       * @param a element to test
       */
      virtual bool IsElement(const Element &a) const = 0;

      virtual bool IsIdentity(const Element &a) const = 0;

      /**
       * Return an integer in [0, q)
       */
      virtual Integer RandomExponent() const = 0;

      /**
       * Return a random element of the group
       */
      virtual Element RandomElement() const = 0;

      //virtual Element GetModulus() const = 0;

      virtual Element GetGenerator() const = 0;

      virtual Integer GetOrder() const = 0;

      virtual Element GetIdentity() const = 0;

      virtual int BytesPerElement() const = 0;

      /**
       * Encode ByteArray into group element. Fails if the 
       * byte array is too long -- make sure that the byte
       * array is shorter than BytesPerElement()
       * @param input QByteArray to encode
       */
      virtual Element EncodeBytes(const QByteArray &in) const = 0;

      /**
       * Decode a group element into a QByteArray
       * @param a the element containing the string
       * @param out reference in which to return string
       * @returns true if everything is okay, false if cannot read
       *          string
       */
      virtual bool DecodeBytes(const Element &a, QByteArray &out) const = 0;

      virtual bool IsProbablyValid() const = 0;

      virtual QByteArray GetByteArray() const = 0;

    private:

  };

}
}
}

#endif
