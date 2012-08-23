#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_GROUP_H_GUARD

#include <QSharedPointer>
#include <PBC.h>

#include "AbstractGroup.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class PairingGroup : public AbstractGroup {

    public:

      /**
       * Destructor
       */
      virtual ~PairingGroup() {}

      /**
       * Multiply two points
       * @param a first operand 
       * @param b second operand 
       */
      virtual Element Multiply(const Element &a, const Element &b) const = 0;

      /**
       * Exponentiate a point by scalar exp
       * @param a base
       * @param exp exponent
       */
      virtual Element Exponentiate(const Element &a, const Integer &exp) const = 0;

      /**
       * Compute (e1^a1 * e2^a2). Generally this can be done much faster
       * than two separate operations.
       * @param a1 base 1
       * @param e1 exponent 1
       * @param a2 base 2
       * @param e2 exponent 2
       */
      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const = 0;

      /**
       * Compute b such that ab = 1 (identity)
       * @param a element to invert
       */
      virtual Element Inverse(const Element &a) const = 0;

      /**
       * Serialize the element as a QByteArray
       * @param a element to serialize 
       */
      virtual QByteArray ElementToByteArray(const Element &a) const = 0;

      /**
       * Unserialize an element from a QByteArray
       * @param bytes the byte array to unserialize
       */
      virtual Element ElementFromByteArray(const QByteArray &bytes) const = 0;

      /**
       * Return true if a is an element of the group 
       * @param a element to test
       */
      virtual bool IsElement(const Element &) const { 
        // PBC does not support this operation
        return true; 
      }

      /**
       * Return true if a == 1 (identity)
       * @param a element to test
       */
      virtual bool IsIdentity(const Element &a) const = 0;

      /**
       * Return an integer in [0, q)
       */
      virtual Integer RandomExponent() const;

      /**
       * Return a random point on the curve
       */
      virtual Element RandomElement() const = 0;

      /**
       * Return the group generating point (g)
       */
      inline virtual Element GetGenerator() const 
      {
        return _generator;
      }
      
      /**
       * Return the group order (q)
       */
      inline virtual Integer GetOrder() const 
      {
        return _order;
      }

      /**
       * Return the group identity element O
       */
      inline virtual Element GetIdentity() const
      {
        return _identity;
      }

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
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

      /**
       * Check if the group is probably valid. It's hard to
       * check in general, so this is just a "best effort" test.
       */
      virtual bool IsProbablyValid() const {
        // PBC does not support this
        return true;
      }

      /**
       * Get a byte array representation of the group
       */
      inline virtual QByteArray GetByteArray() const {
        return _param_str;
      }

    protected:
      // Protected constructor
      PairingGroup();

      inline const Pairing &GetPairing() const { return _pairing; }
      inline void SetIdentity(Element e) { _identity = e; }
      inline void SetGenerator(Element e) { _generator = e; }
      Zr IntegerToZr(const Integer &in) const;
      
      QByteArray _param_str;

      Pairing _pairing;
      Element _identity;
      Element _generator;
      Integer _order;

    private:
      static const char _param_bytes[]; 
      static const char _order_bytes[]; 

  };

}
}
}

#endif
