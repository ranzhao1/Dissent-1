#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(PairingGroupG1, Basic)
  {
    AbstractGroup_Basic(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Basic)
  {
    AbstractGroup_Basic(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingGroupG1, IsElement)
  {
    AbstractGroup_IsElement(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, IsElement)
  {
    AbstractGroup_IsElement(PairingGTGroup::ProductionFixed());
  }
  
  TEST(PairingGroupG1, RandomExponent)
  {
    AbstractGroup_RandomExponent(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, RandomExponent)
  {
    AbstractGroup_RandomExponent(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingGroupG1, Multiplication)
  {
    AbstractGroup_Multiplication(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Multiplication)
  {
    AbstractGroup_Multiplication(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingGroupG1, Exponentiation)
  {
    AbstractGroup_Exponentiation(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Exponentiation)
  {
    AbstractGroup_Exponentiation(PairingGTGroup::ProductionFixed());
  }

  TEST(PairingWrapper, Basic)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::ProductionFixed());
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::ProductionFixed());

    PairingWrapper wrap(group1, groupT);
    Pairing p(group1->GetByteArray().constData(), group1->GetByteArray().count());

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());
    ASSERT_EQ(group1->GetByteArray(), wrap.GetByteArray());

    Element a = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer r = group1->RandomExponent();

      Element lhs = wrap.Apply(a, group1->Multiply(a, a));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = wrap.Apply(group1->Exponentiate(a, Integer(2)), a);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST(PairingWrapper, Exponent)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::ProductionFixed());
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::ProductionFixed());

    PairingWrapper wrap(group1, groupT);
    Pairing p(group1->GetByteArray().constData(), group1->GetByteArray().count());

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());
    ASSERT_EQ(group1->GetByteArray(), wrap.GetByteArray());

    Element a = group1->RandomElement();
    Element b = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer r = group1->RandomExponent();

      Element lhs = wrap.Apply(a, b);
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = wrap.Apply(b, a);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);

      lhs = wrap.Apply(a, group1->Exponentiate(b, r));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      rhs = wrap.Apply(group1->Exponentiate(a, r), b);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST(PairingWrapper, DoubleExponent)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::ProductionFixed());
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::ProductionFixed());

    PairingWrapper wrap(group1, groupT);
    Pairing p(group1->GetByteArray().constData(), group1->GetByteArray().count());

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());
    ASSERT_EQ(group1->GetByteArray(), wrap.GetByteArray());

    Element a = group1->RandomElement();
    Element b = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer ra = group1->RandomExponent();
      Integer rb = group1->RandomExponent();

      Element lhs = wrap.Apply(group1->Exponentiate(a, ra), group1->Exponentiate(b, rb));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = wrap.Apply(b, a);
      rhs = groupT->Exponentiate(rhs, ra);
      rhs = groupT->Exponentiate(rhs, rb);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

}
}
