#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_GROUP_H_GUARD

#include <QSharedPointer>

#include "AbstractGroup.hpp"
#include "IntegerElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class IntegerGroup : public AbstractGroup {

    public:

      /**
       * Constructor
       * @param p must be a safe prime -- should have the
       *        form p = 2q+1 for a prime q
       * @param g must generate the large prime-order subgroup 
       *        group of Z*_p
       */
      IntegerGroup(Integer p, Integer g);

      static QSharedPointer<IntegerGroup> Generate(int p_bits);

      static QSharedPointer<IntegerGroup> ProductionFixed();

      static QSharedPointer<IntegerGroup> TestingFixed();

      static QSharedPointer<IntegerGroup> Zero();

      virtual ~IntegerGroup() {}

      virtual Element Multiply(const Element &a, const Element &b) const;

      virtual Element Exponentiate(const Element &a, const Integer &exp) const;

      virtual Element CascadeExponentiate(const Element &a1, const Integer &e1,
          const Element &a2, const Integer &e2) const;

      virtual Element Inverse(const Element &a) const;

      virtual QByteArray ElementToByteArray(const Element &a) const;

      virtual Element ElementFromByteArray(const QByteArray &bytes) const;

      virtual bool IsElement(const Element &a) const;

      virtual bool IsIdentity(const Element &a) const;

      virtual Integer RandomExponent() const;

      virtual Element RandomElement() const;

      inline virtual Integer GetModulus() const { 
        return _p;
      }

      inline virtual Element GetGenerator() const { 
        return Element(new IntegerElementData(_g)); 
      }
      
      inline virtual Integer GetOrder() const { 
        return _q; 
      }

      inline virtual Element GetIdentity() const { 
        return Element(new IntegerElementData(Integer(1))); 
      }

      virtual int BytesPerElement() const {
        return (_q.GetByteCount() - 4);
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

      virtual bool IsProbablyValid() const;

      virtual QByteArray GetByteArray() const;

    private:

      Integer GetInteger(const Element &e) const;

      Integer _p;

      /**
       * Equal to (p-1)/2. Useful for testing if an element
       * is a QR mod p, since:
       *
       *   (a is QR_p) iff (a^{(p-1)/2} == a^q == 1 mod p)
       */
      Integer _q;

      /**
       * Generator of group
       */
      Integer _g;

  };

}
}
}

#endif
