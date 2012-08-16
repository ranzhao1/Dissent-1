#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_EC_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_EC_GROUP_H_GUARD

#include <QSharedPointer>

#include "Crypto/CppIntegerData.hpp"
#include "AbstractGroup.hpp"
#include "ECElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This class represents an elliptic curve modulo
   * a prime. The curves take the form:
   *   y^2 = x^3 + ax + b (mod p)
   */
  class ECGroup : public AbstractGroup {

    public:

      /**
       * Constructor 
       * @param p must be a prime 
       * @param q order of the field
       * @param a linear coefficient of curve
       * @param b constant term of curve
       * @param gx x-coordinate of generating point
       * @param gy y-coordinate of generating point
       */
      ECGroup(Integer p, Integer q,
          Integer a, Integer b, Integer gx, Integer gy);

      /**
       * Get a fixed group using the RFC 5093 256-bit curve
       */
      static QSharedPointer<ECGroup> ProductionFixed();

      /**
       * Destructor
       */
      virtual ~ECGroup() {}

      /**
       * Add two elliptic curve points
       * @param a first operand 
       * @param b second operand 
       */
      virtual Element Multiply(const Element &a, const Element &b) const;

      /**
       * Multiply an EC point by scalar exp
       * @param a base
       * @param exp exponent
       */
      virtual Element Exponentiate(const Element &a, const Integer &exp) const;

      /**
       * Compute (e1a1 + e2a2). Generally this can be done much faster
       * than two separate operations.
       * @param a1 base 1
       * @param e1 exponent 1
       * @param a2 base 2
       * @param e2 exponent 2
       */
      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const;

      /**
       * Compute b such that a+b = O (identity)
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
       * Return true if a is an element of the group -- i.e., if 
       * a is a point on the curve
       * @param a element to test
       */
      virtual bool IsElement(const Element &a) const;

      /**
       * Return true if a == O (identity)
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
      inline virtual Element GetGenerator() const { 
        return Element(new ECElementData(_g)); 
      }
      
      /**
       * Return the group order (q)
       */
      inline virtual Integer GetOrder() const { 
        return _q;
      }

      /**
       * Return the group identity element O
       */
      inline virtual Element GetIdentity() const { 
        return Element(new ECElementData(_curve.Identity())); 
      }

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      virtual int BytesPerElement() const {
        return 0;
      }

      /**
       * Encode ByteArray into group element. Fails if the 
       * byte array is too long -- make sure that the byte
       * array is shorter than BytesPerElement()
       * @param input QByteArray to encode
       */
      virtual Element EncodeBytes(const QByteArray &in) const;

      /**
       * Decode a group element into a QByteArray
       * @param a the element containing the string
       * @param out reference in which to return string
       * @returns true if everything is okay, false if cannot read
       *          string
       */
      virtual bool DecodeBytes(const Element &a, QByteArray &out) const;

      /**
       * Check if the group is probably valid. It's hard to
       * check in general, so this is just a "best effort" test.
       */
      virtual bool IsProbablyValid() const;

      /**
       * Get a byte array representation of the group
       */
      virtual QByteArray GetByteArray() const;

      /**
       * Get size of the EC field (i.e., the modulus p)
       */
      inline Integer GetFieldSize() const { return FromCryptoInt(_curve.FieldSize()); }

    private:

      CryptoPP::ECPPoint GetPoint(const Element &e) const;
      inline static CryptoPP::Integer ToCryptoInt(const Integer &e) 
      {
        // Hex encoding does not include minus sign        
        CryptoPP::Integer i(("0x"+e.GetByteArray().toHex()).constData());
        if(e < 0) i.SetNegative();
        return i;
      }

      inline static Integer FromCryptoInt(const CryptoPP::Integer &i)
      {
        return Integer(new CppIntegerData(i));
      }

      CryptoPP::ECP _curve;
      Integer _q;
      CryptoPP::ECPPoint _g;

  };

}
}
}

#endif
