#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class CppECGroupTest : 
    public ::testing::TestWithParam<int> {
  };

  TEST_P(CppECGroupTest, Basic)
  {
    AbstractGroup_Basic(CppECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(CppECGroupTest, IsElement) 
  {
    AbstractGroup_IsElement(CppECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(CppECGroupTest, RandomExponent) 
  {
    AbstractGroup_RandomExponent(CppECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(CppECGroupTest, NotElement) 
  {
    QSharedPointer<CppECGroup> group = CppECGroup::GetGroup((ECParams::CurveName)GetParam());

    int count = 0;
    for(int i=0; i<100; i++) {
      Integer x = Integer::GetRandomInteger(0, group->GetFieldSize());
      Integer y = Integer::GetRandomInteger(0, group->GetFieldSize());

      CryptoPP::ECPPoint p(CryptoPP::Integer(x.GetByteArray().constData()), 
          CryptoPP::Integer(y.GetByteArray().constData()));
      Element e(new CppECElementData(p));
      if(group->IsElement(e)) count++;
    }

    EXPECT_TRUE(count < 5);
  }
  
  TEST_P(CppECGroupTest, Multiplication) 
  {
    AbstractGroup_Multiplication(CppECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(CppECGroupTest, Exponentiation) 
  {
    AbstractGroup_Exponentiation(CppECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(CppECGroupTest, Serialize)
  {
    AbstractGroup_Serialize(CppECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(CppECGroupTest, Encode)
  {
    AbstractGroup_Encode(CppECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  INSTANTIATE_TEST_CASE_P(CppECGroupTest, CppECGroupTest,
      ::testing::Range(0, (int)ECParams::INVALID));

}
}
