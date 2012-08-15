#ifndef DISSENT_CRYPTO_ABSTRACT_GROUP_ABSTRACT_GROUP_H_GUARD
#define DISSENT_CRYPTO_ABSTRACT_GROUP_ABSTRACT_GROUP_H_GUARD

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

      virtual Element Inverse(const Element &a) const = 0;

      virtual QByteArray GetByteArray(const Element &a) const = 0;

      virtual Element FromByteArray(const QByteArray &bytes) const = 0;

      virtual bool IsValid(const Element &a) const = 0;

      virtual bool IsIdentity(const Element &a) const = 0;

      virtual Integer RandomExponent() const = 0;

      virtual Element RandomElement() const = 0;

      virtual Element GetModulus() const = 0;

      virtual Element GetGenerator() const = 0;

      virtual Integer GetOrder() const = 0;

    private:

  };

}
}
}

#endif
