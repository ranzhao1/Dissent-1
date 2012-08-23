
#include <gmp.h>

#include "PairingGTGroup.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  QSharedPointer<PairingGTGroup> PairingGTGroup::ProductionFixed()
  {
    const unsigned char generatorT_str[] = 
          "[795021851328020033538485063506889346340348790473894916238866664663"
          "9150616295447802746802629878913026197716951475548418491838118674043"
          "19363059257332521718605, 678205493899729155525770728889429548658760"
          "4094995139744601370103366002392787037597944280636791426667700330308"
          "27851052673787698901892811486811655628074359316]";

    QSharedPointer<PairingGTGroup> group(new PairingGTGroup());

    GT identity(group->GetPairing(), true);
    Q_ASSERT(identity.isElementPresent());

    GT generator(group->GetPairing(), generatorT_str, sizeof(generatorT_str), 10);
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
    return Element(new PairingElementData<GT>(
          GetElement(_generator) ^ IntegerToZr(RandomExponent())));
  }

  int PairingGTGroup::BytesPerElement() const
  {
    return GetElement(_generator).getElementSize();
  }

  Element PairingGTGroup::EncodeBytes(const QByteArray &) const
  {
    return Element(NULL);
  }
 
  bool PairingGTGroup::DecodeBytes(const Element &, QByteArray &) const
  {
    return false;
  }

}
}
}
