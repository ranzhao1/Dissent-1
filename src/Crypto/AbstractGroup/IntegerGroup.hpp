#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_INTEGER_GROUP_H_GUARD

#include "AbstractGroup.hpp"
#include "IntegerElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  class IntegerGroup : public AbstractGroup {

    public:

      IntegerGroup(Integer p, Integer q, Integer g);

      virtual ~IntegerGroup() {}

      virtual Element Multiply(const Element &a, const Element &b) const;

      virtual Element Exponentiate(const Element &a, const Integer &exp) const;

      virtual Element Inverse(const Element &a) const;

      virtual QByteArray GetByteArray(const Element &a) const;

      virtual Element FromByteArray(const QByteArray &bytes) const;

      virtual bool IsValid(const Element &a) const;

      virtual bool IsIdentity(const Element &a) const;

      virtual Integer RandomExponent() const;

      virtual Element RandomElement() const;

      inline virtual Element GetModulus() const { 
        return Element(new IntegerElementData(_p)); 
      }

      inline virtual Element GetGenerator() const { 
        return Element(new IntegerElementData(_g)); 
      }
      
      inline virtual Integer GetOrder() const { 
        return _q; 
      }

    private:

      Integer GetInteger(const Element &e) const;

      Integer _p, _q, _g;

  };

}
}
}

#endif
