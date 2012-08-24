
#include <gmp.h>

#include "PairingG1Group.hpp"
#include "PairingElementData.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  QSharedPointer<PairingG1Group> PairingG1Group::ProductionFixed()
  {
    const unsigned char generator1_str[] = "generator";

    QSharedPointer<PairingG1Group> group(new PairingG1Group());

    G1 identity(group->GetPairing(), true);
    Q_ASSERT(identity.isElementPresent());

    // Create generator from hash
    G1 generator(group->GetPairing(), generator1_str, sizeof(generator1_str));
    Q_ASSERT(generator.isElementPresent());

    group->SetIdentity(Element(new PairingElementData<G1>(identity)));
    group->SetGenerator(Element(new PairingElementData<G1>(generator)));

    Element ident = group->GetIdentity();
    Element gen = group->GetGenerator();

    return group;
  }

  PairingG1Group::PairingG1Group() :
    PairingGroup() {}

  PairingG1Group::~PairingG1Group() 
  {
  }

  Element PairingG1Group::Multiply(const Element &a, const Element &b) const
  {
    G1 e_a(GetElement(a));
    G1 e_b(GetElement(b));

    return Element(new PairingElementData<G1>(e_a * e_b));
  }

  Element PairingG1Group::Exponentiate(const Element &a, const Integer &exp) const
  { 
    Zr e_exp(IntegerToZr(exp));
    G1 e_a(GetElement(a));

    return Element(new PairingElementData<G1>(e_a ^ e_exp));
  }
  
  Element PairingG1Group::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    Zr e_exp1(IntegerToZr(e1));
    G1 e_a1(GetElement(a1));
    Zr e_exp2(IntegerToZr(e2));
    G1 e_a2(GetElement(a2));
    
    return Element(new PairingElementData<G1>((e_a1 ^ e_exp1)*(e_a2 ^ e_exp2)));
  }

  Element PairingG1Group::Inverse(const Element &a) const
  {
    return Element(new PairingElementData<G1>(GetElement(a).inverse()));
  }
  
  QByteArray PairingG1Group::ElementToByteArray(const Element &a) const
  {
    std::string s = GetElement(a).toString(false);
    Q_ASSERT(s.length() > 1);
    return QByteArray(s.c_str(), s.length());
  }
  
  Element PairingG1Group::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    Q_ASSERT(bytes.count());
    const unsigned char *data = (const unsigned char*)(bytes.constData());
    G1 a(_pairing, data, bytes.count(), false);
    Q_ASSERT(a.isElementPresent());
    return Element(new PairingElementData<G1>(a));
  }

  bool PairingG1Group::IsIdentity(const Element &a) const 
  {
    return GetElement(a).isIdentity();
  }


  Element PairingG1Group::RandomElement() const
  {
    return Element(new PairingElementData<G1>(G1(_pairing, false)));
  }

  int PairingG1Group::BytesPerElement() const
  {
    return GetElement(_generator).getElementSize(false);
  }

  Element PairingG1Group::EncodeBytes(const QByteArray &) const
  {
    return Element(NULL);
  }
 
  bool PairingG1Group::DecodeBytes(const Element &, QByteArray &) const
  {
    return false;
  }
}
}
}
