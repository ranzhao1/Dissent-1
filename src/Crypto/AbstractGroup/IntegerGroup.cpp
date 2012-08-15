
#include "IntegerElementData.hpp"
#include "IntegerGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  IntegerGroup::IntegerGroup(Integer p, Integer q, Integer g) :
      _p(p), 
      _q(q), 
      _g(g) 
    {};

  Element IntegerGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new IntegerElementData((GetInteger(a)*GetInteger(b)) % _p)); 
  }

  Element IntegerGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new IntegerElementData(GetInteger(a).Pow(exp, _p))); 
  }

  Element IntegerGroup::Inverse(const Element &a) const
  {
    return Element(new IntegerElementData(GetInteger(a).ModInverse(_p)));
  }
  
  QByteArray IntegerGroup::GetByteArray(const Element &a) const
  {
    return GetInteger(a).GetByteArray();
  }
  
  Element IntegerGroup::FromByteArray(const QByteArray &bytes) const 
  {
    return Element(new IntegerElementData(Integer(bytes)));
  }

  bool IntegerGroup::IsValid(const Element &a) const 
  {
    return (GetInteger(a).Pow(_q, _p) == 1);
  }

  bool IntegerGroup::IsIdentity(const Element &a) const 
  {
    return (GetInteger(a) == 1);
  }

  Integer IntegerGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(0, _q, false); 
  }

  Element IntegerGroup::RandomElement() const
  {
    return Element(new IntegerElementData(_g.Pow(RandomExponent(), _p)));
  }

  Integer IntegerGroup::GetInteger(const Element &e) const
  {
    return IntegerElementData::GetInteger(e.GetData());
  }

}
}
}
