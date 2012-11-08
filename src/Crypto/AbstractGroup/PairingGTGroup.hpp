#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_GT_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_PAIRING_GT_GROUP_H_GUARD

#include <gmp.h>

#include "OpenECGroup.hpp"
#include "PairingGroup.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class PairingGTGroup : public PairingGroup {

    public:
      /**
       * Get a fixed group 
       */
      static QSharedPointer<PairingGTGroup> GetGroup(GroupSize size);

      /**
       * Copy constructor 
       */
      PairingGTGroup(const PairingGTGroup &other); 

      /**
       * Destructor
       */
      virtual ~PairingGTGroup(); 

      /**
       * Return a pointer to a copy of this group
       */
      virtual QSharedPointer<AbstractGroup> Copy() const;

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
       * Return true if a == 1 (identity)
       * @param a element to test
       */
      virtual bool IsIdentity(const Element &a) const;

      /**
       * Return a random point on the curve
       */
      virtual Element RandomElement() const;

      /**
       * Return the number of bytes that can be
       * encoded in a single group element
       */
      virtual int BytesPerElement() const;

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

      virtual Element ApplyPairing(const Element &a, const Element &b) const;

      /**
       * Return true if element is a generator
       */
      virtual inline bool IsGenerator(const Element &a) const { 
        qDebug() << "elm" << IsElement(a);
        qDebug() << "id" << IsIdentity(a);
        return IsElement(a) && !IsIdentity(a);
      }

      /**
       * Return true if is element of group
       */
      virtual bool IsElement(const Element &a) const;

      /**
       * Return a printable representation of the group
       */
      virtual inline QString ToString() const 
      {
        return QString("PairingGTGroup");
      }

       virtual Element ElementFromHash(const QString data);

    private:

      // Private Constructor
      PairingGTGroup(GroupSize size);

      inline GT GetElement(const Element &a) const
      {
        return GT(PairingElementData<GT>::GetElement(a.GetData())); 
      }

      void SetupGroup();
      void GetPBCElementCoordinates(const Element &a, Integer &x, Integer &y) const;
      bool SolveForY(const Integer &x, Integer &y) const;
      Element IntegersToElement(const Integer &x, Integer &y) const;
  };

}
}
}

#endif
