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

      static QSharedPointer<PairingGroup> ProductionG1Fixed();
      static QSharedPointer<PairingGroup> ProductionGTFixed();

      /**
       * Destructor
       */
      virtual ~PairingGroup(); 

      /**
       * Multiply two points
       * @param a first operand 
       * @param b second operand 
       */
      virtual Element Multiply(const Element &a, const Element &b) const;

      /**
       * Exponentiate a point by scalar exp
       * @param a base
       * @param exp exponent
       */
      virtual Element Exponentiate(const Element &a, const Integer &exp) const;

      /**
       * Compute (e1^a1 * e2^a2). Generally this can be done much faster
       * than two separate operations.
       * @param a1 base 1
       * @param e1 exponent 1
       * @param a2 base 2
       * @param e2 exponent 2
       */
      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const;

      /**
       * Compute b such that ab = 1 (identity)
       * @param a element to invert
       */
      virtual Element Inverse(const Element &a) const;

      /**
       * Serialize the element as a QByteArray
       * @param a element to serialize 
       */
      virtual QByteArray ElementToByteArray(const Element &a) const;

      /**
       * Unserialize an element from a QByteArray
       * @param bytes the byte array to unserialize
       */
      virtual Element ElementFromByteArray(const QByteArray &bytes) const;

      /**
       * Return true if a is an element of the group 
       * @param a element to test
       */
      virtual bool IsElement(const Element &a) const;

      /**
       * Return true if a == 1 (identity)
       * @param a element to test
       */
      virtual bool IsIdentity(const Element &a) const;

      /**
       * Return an integer in [0, q)
       */
      virtual Integer RandomExponent() const;

      /**
       * Return a random point on the curve
       */
      virtual Element RandomElement() const;

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
      virtual bool IsProbablyValid() const;

      /**
       * Get a byte array representation of the group
       */
      virtual QByteArray GetByteArray() const;

    protected:
      inline QSharedPointer<G> GetElement(const Element &e) const {
        return PairingElementData::GetElement(e.GetData());
      }
 
      // Private constructor
      static QSharedPointer<PairingGroup> Create(PairingElementType type);
      PairingGroup(const char *param_str, int param_len, PairingElementType type);

      Pairing _pairing;

      Integer _order;
      Element _generator;
      Element _identity;

      QByteArray _param_str;

      PairingElementType _type;
  };

}
}
}

#endif
