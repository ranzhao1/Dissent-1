#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class PairingGroupTest : 
    public ::testing::TestWithParam<int> {
  };

  TEST_P(PairingGroupTest, G1Basic)
  {
    AbstractGroup_Basic(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, GTBasic)
  {
    AbstractGroup_Basic(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, G1IsElement)
  {
    AbstractGroup_IsElement(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, GTIsElement)
  {
    AbstractGroup_IsElement(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));
  }
  
  TEST_P(PairingGroupTest, G1RandomExponent)
  {
    AbstractGroup_RandomExponent(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, GTRandomExponent)
  {
    AbstractGroup_RandomExponent(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, G1Multiplication)
  {
    AbstractGroup_Multiplication(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, GTMultiplication)
  {
    AbstractGroup_Multiplication(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, G1Exponentiation)
  {
    AbstractGroup_Exponentiation(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, GTExponentiation)
  {
    AbstractGroup_Exponentiation(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, G1Serialize)
  {
    AbstractGroup_Serialize(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, GTSerialize)
  {
    AbstractGroup_Serialize(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  /* not implemented yet
  TEST_P(PairingGroupTestG1, Encode)
  {
    AbstractGroup_Encode(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
  }
  */

  TEST_P(PairingGroupTest, GTEncode)
  {
    AbstractGroup_Encode(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));
  }

  TEST_P(PairingGroupTest, Basic)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Element a = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer r = group1->RandomExponent();

      Element lhs = groupT->ApplyPairing(a, group1->Multiply(a, a));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = groupT->ApplyPairing(group1->Exponentiate(a, Integer(2)), a);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST_P(PairingGroupTest, Exponent)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Element a = group1->RandomElement();
    Element b = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer r = group1->RandomExponent();

      Element lhs = groupT->ApplyPairing(a, b);
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = groupT->ApplyPairing(b, a);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);

      lhs = groupT->ApplyPairing(a, group1->Exponentiate(b, r));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      rhs = groupT->ApplyPairing(group1->Exponentiate(a, r), b);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST_P(PairingGroupTest, DoubleExponent)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Element a = group1->RandomElement();
    Element b = group1->RandomElement();
    for(int i=0; i<100; i++) {
      Integer ra = group1->RandomExponent();
      Integer rb = group1->RandomExponent();

      Element lhs = groupT->ApplyPairing(group1->Exponentiate(a, ra), group1->Exponentiate(b, rb));
      EXPECT_FALSE(groupT->IsIdentity(lhs));

      Element rhs = groupT->ApplyPairing(b, a);
      rhs = groupT->Exponentiate(rhs, ra);
      rhs = groupT->Exponentiate(rhs, rb);
      EXPECT_FALSE(groupT->IsIdentity(rhs));

      EXPECT_EQ(lhs, rhs);
    }
  }

  TEST_P(PairingGroupTest, EncodeAndPair)
  {
    QSharedPointer<PairingG1Group> group1(PairingG1Group::GetGroup((PairingGroup::GroupSize)GetParam()));
    QSharedPointer<PairingGTGroup> groupT(PairingGTGroup::GetGroup((PairingGroup::GroupSize)GetParam()));

    ASSERT_EQ(group1->GetByteArray(), groupT->GetByteArray());

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray out;

    for(int i=0; i<100; i++) {
      QByteArray msg(rand->GetInt(1, groupT->BytesPerElement()), 0);
      rand->GenerateBlock(msg);

      Element a = group1->RandomElement();
      Element b = group1->RandomElement();

      Element m = groupT->EncodeBytes(msg);

      // compute c = m * e(a,b) * e(a, b^-1)
      Element t1 = groupT->ApplyPairing(a, b);
      Element t2 = groupT->ApplyPairing(a, group1->Inverse(b));

      Element c = groupT->Multiply(groupT->Multiply(t1, t2), m);

      // check m == c
      EXPECT_EQ(m, c);

      EXPECT_TRUE(groupT->DecodeBytes(c, out));
      EXPECT_EQ(msg, out);
    }
  }

  INSTANTIATE_TEST_CASE_P(PairingGroupTest, PairingGroupTest,
      ::testing::Range(0, (int)PairingGroup::INVALID));
}
}
