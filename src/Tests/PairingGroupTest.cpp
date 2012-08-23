#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  void PairingGroupBasic(QSharedPointer<PairingGroup> group)
  {
    Element g = group->GetGenerator();

    ASSERT_TRUE(group->IsProbablyValid());
    ASSERT_EQ(g, g);
    ASSERT_TRUE(group->IsElement(g));
    ASSERT_FALSE(group->IsIdentity(g));
    ASSERT_TRUE(group->IsIdentity(group->Exponentiate(g, group->GetOrder())));
    ASSERT_TRUE(group->IsElement(group->Multiply(g, g)));
  }

  TEST(PairingGroupG1, Basic)
  {
    PairingGroupBasic(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Basic)
  {
    PairingGroupBasic(PairingGTGroup::ProductionFixed());
  }

  void PairingGroupIsElement(QSharedPointer<PairingGroup> group)
  {
    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->RandomElement()));
    }
  }

  TEST(PairingGroupG1, IsElement)
  {
    PairingGroupIsElement(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, IsElement)
  {
    PairingGroupIsElement(PairingGTGroup::ProductionFixed());
  }

  void PairingGroupRandomExponent(QSharedPointer<PairingGroup> group)
  {
    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->Exponentiate(group->GetGenerator(),
              group->RandomExponent())));
    }
  }
  
  TEST(PairingGroupG1, RandomExponent)
  {
    PairingGroupRandomExponent(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, RandomExponent)
  {
    PairingGroupRandomExponent(PairingGTGroup::ProductionFixed());
  }

  void PairingGroupMultiplication(QSharedPointer<PairingGroup> group)
  {
    for(int i=0; i<100; i++) {
      Element a = group->RandomElement();
      Element b = group->RandomElement();
      Integer c = group->RandomExponent();
      Element ab = group->Multiply(a, b);
      Element a2c = group->Exponentiate(a, c);
      Element b2c = group->Exponentiate(b, c);

      EXPECT_EQ(ab, group->Multiply(b, a));

      // (a*b)^c  ==  (a^c)*(b^c)
      EXPECT_EQ(group->Exponentiate(ab, c), group->Multiply(a2c, b2c));
      EXPECT_EQ(group->Exponentiate(ab, c), group->CascadeExponentiate(a, c, b, c));
    }
  }

  TEST(PairingGroupG1, Multiplication)
  {
    PairingGroupMultiplication(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Multiplication)
  {
    PairingGroupMultiplication(PairingGTGroup::ProductionFixed());
  }

  void PairingGroupExponentiation(QSharedPointer<PairingGroup> group)
  {
    for(int i=0; i<100; i++) {
      Element a = group->RandomElement();
      Element b = group->RandomElement();
      Integer c = group->RandomExponent();

      EXPECT_EQ(a, group->Exponentiate(a, Integer(1)));
    }
  }

  TEST(PairingGroupG1, Exponentiation)
  {
    PairingGroupExponentiation(PairingG1Group::ProductionFixed());
  }

  TEST(PairingGroupGT, Exponentiation)
  {
    PairingGroupExponentiation(PairingGTGroup::ProductionFixed());
  }

}
}
