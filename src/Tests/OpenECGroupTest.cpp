#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class OpenECGroupTest : 
    public ::testing::TestWithParam<int> {
  };

  TEST_P(OpenECGroupTest, Basic)
  {
    AbstractGroup_Basic(OpenECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(OpenECGroupTest, IsElement) 
  {
    AbstractGroup_IsElement(OpenECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(OpenECGroupTest, RandomExponent) 
  {
    AbstractGroup_RandomExponent(OpenECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(OpenECGroupTest, Multiplication) 
  {
    AbstractGroup_Multiplication(OpenECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(OpenECGroupTest, Exponentiation) 
  {
    AbstractGroup_Exponentiation(OpenECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(OpenECGroupTest, Serialize)
  {
    AbstractGroup_Serialize(OpenECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(OpenECGroupTest, Encode)
  {
    AbstractGroup_Encode(OpenECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  INSTANTIATE_TEST_CASE_P(OpenECGroupTest, OpenECGroupTest,
      ::testing::Range(0, (int)ECParams::INVALID));

}
}
