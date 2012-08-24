
#include <gmp.h>

#include "PairingGTGroup.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  QSharedPointer<PairingGTGroup> PairingGTGroup::ProductionFixed()
  {
    const unsigned char generatorT_str[] = "generator";

    QSharedPointer<PairingGTGroup> group(new PairingGTGroup());

    GT identity(group->GetPairing(), true);
    Q_ASSERT(identity.isElementPresent());

    // Create generator from hash
    GT generator(group->GetPairing(), generatorT_str, sizeof(generatorT_str));
    Q_ASSERT(generator.isElementPresent());

    group->SetIdentity(Element(new PairingElementData<GT>(identity)));
    group->SetGenerator(Element(new PairingElementData<GT>(generator)));

    Element ident = group->GetIdentity();
    Element gen = group->GetGenerator();

    return group;
  }

  PairingGTGroup::PairingGTGroup() :
    PairingGroup() {}

  PairingGTGroup::~PairingGTGroup() 
  {
  }

  Element PairingGTGroup::Multiply(const Element &a, const Element &b) const
  {
    GT e_a(GetElement(a));
    GT e_b(GetElement(b));

    return Element(new PairingElementData<GT>(e_a * e_b));
  }

  Element PairingGTGroup::Exponentiate(const Element &a, const Integer &exp) const
  { 
    Zr e_exp(IntegerToZr(exp));
    GT e_a(GetElement(a));

    return Element(new PairingElementData<GT>(e_a ^ e_exp));
  }
  
  Element PairingGTGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    Zr e_exp1(IntegerToZr(e1));
    GT e_a1(GetElement(a1));
    Zr e_exp2(IntegerToZr(e2));
    GT e_a2(GetElement(a2));
    
    return Element(new PairingElementData<GT>((e_a1 ^ e_exp1)*(e_a2 ^ e_exp2)));
  }

  Element PairingGTGroup::Inverse(const Element &a) const
  {
    return Element(new PairingElementData<GT>(GetElement(a).inverse()));
  }
  
  QByteArray PairingGTGroup::ElementToByteArray(const Element &a) const
  {
    std::string s = GetElement(a).toString();
    Q_ASSERT(s.length() > 1);
    return QByteArray(s.c_str(), s.length());
  }
  
  Element PairingGTGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    Q_ASSERT(bytes.count());
    const unsigned char *data = (const unsigned char*)(bytes.constData());
    GT a(_pairing, data, bytes.count(), false);
    Q_ASSERT(a.isElementPresent());
    return Element(new PairingElementData<GT>(a));
  }

  bool PairingGTGroup::IsIdentity(const Element &a) const 
  {
    return GetElement(a).isIdentity();
  }

  Element PairingGTGroup::RandomElement() const
  {
    return Element(new PairingElementData<GT>(GT(_pairing, false)));
  }

  int PairingGTGroup::BytesPerElement() const
  {
    return GetElement(_generator).getElementSize();
  }

  Element PairingGTGroup::EncodeBytes(const QByteArray &) const
  {
    qFatal("Not implemented");
    return Element(NULL);
  }
 
  bool PairingGTGroup::DecodeBytes(const Element &, QByteArray &) const
  {
    qFatal("Not implemented");
    return false;
  }

}
}
}
