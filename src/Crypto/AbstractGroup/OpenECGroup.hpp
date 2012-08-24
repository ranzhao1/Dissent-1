#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_OPEN_EC_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_OPEN_EC_GROUP_H_GUARD

#include <openssl/ec.h>
#include <QSharedPointer>

#include "AbstractGroup.hpp"
#include "OpenECElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  /**
   * This class represents an elliptic curve modulo
   * a prime. The curves take the form:
   *   y^2 = x^3 + ax + b (mod p)
   * This class uses an OpenSSL implementation.
   */
  class OpenECGroup : public AbstractGroup {

    public:

      /**
       * Constructor: OpenECGroup will free all 
       * of these BIGNUMs on exit.
       * @param p must be a prime 
       * @param q order of the field
       * @param a linear coefficient of curve
       * @param b constant term of curve
       * @param gx x-coordinate of generating point
       * @param gy y-coordinate of generating point
       */
      OpenECGroup(BIGNUM *p, BIGNUM *q,
          BIGNUM *a, BIGNUM *b, BIGNUM *gx, BIGNUM *gy);

      /**
       * Get a fixed group using the RFC 5093 256-bit curve
       */
      static QSharedPointer<OpenECGroup> ProductionFixed();

      /**
       * Destructor
       */
      virtual ~OpenECGroup();

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
        return Element(new OpenECElementData(_g)); 
      }
      
      /**
       * Return the group order (q)
       */
      inline virtual Integer GetOrder() const;

      /**
       * Return the group identity element O
       */
      inline virtual Element GetIdentity() const; 

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      inline virtual int BytesPerElement() const {
        // Bytes in field minus bytes in parameter k
        // minus two padding bytes
        return (_field_bytes - _k_bytes - 2);
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
      inline Integer GetFieldSize() const;

    private:

      /**
       * Create a new BIGNUM from Integer. ret
       * must already have been initialized with BN_new()
       */
      void GetInteger(BIGNUM *ret, const Integer &i) const;

      EC_POINT *GetPoint(const Element &e) const;

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

      /** 
       * Try to solve EC equation for y given x
       * @param x coordinate to try
       * @param point returned ECP point if solution found
       * @returns true if found solution
       */
      bool SolveForY(const CryptoPP::Integer &x, Element &point) const;

      BIGNUM *_p;
      BIGNUM *_q;
      BIGNUM *_a;
      BIGNUM *_b;
      BIGNUM *_gx;
      BIGNUM *_gy;

      BIGNUM *_one;

      BIGNUM *_tmp0, *_tmp1;

      BN_CTX *_ctx;
      EC_GROUP *_group;
      EC_POINT *_generator;

      Integer _order;

      /** Serialization parameters */
      static const int _k_bytes = 1;
      static const int _k = (1 << (_k_bytes*8));

  };

}
}
}

#endif
