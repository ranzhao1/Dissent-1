#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class BotanECGroupTest : 
    public ::testing::TestWithParam<int> {
  };

  TEST_P(BotanECGroupTest, Basic)
  {
    AbstractGroup_Basic(BotanECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(BotanECGroupTest, IsElement) 
  {
    AbstractGroup_IsElement(BotanECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(BotanECGroupTest, RandomExponent) 
  {
    AbstractGroup_RandomExponent(BotanECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }
  
  TEST_P(BotanECGroupTest, Multiplication) 
  {
    AbstractGroup_Multiplication(BotanECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(BotanECGroupTest, Exponentiation) 
  {
    AbstractGroup_Exponentiation(BotanECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(BotanECGroupTest, Serialize)
  {
    AbstractGroup_Serialize(BotanECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  TEST_P(BotanECGroupTest, Encode)
  {
    AbstractGroup_Encode(BotanECGroup::GetGroup((ECParams::CurveName)GetParam()));
  }

  INSTANTIATE_TEST_CASE_P(BotanECGroupTest, BotanECGroupTest,
      ::testing::Range(0, (int)ECParams::INVALID));


}
}
