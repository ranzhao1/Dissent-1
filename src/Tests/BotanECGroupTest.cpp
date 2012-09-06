#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(BotanECGroup, Basic)
  {
    AbstractGroup_Basic(BotanECGroup::ProductionFixed());
  }

  TEST(BotanECGroup, IsElement) 
  {
    AbstractGroup_IsElement(BotanECGroup::ProductionFixed());
  }

  TEST(BotanECGroup, RandomExponent) 
  {
    AbstractGroup_RandomExponent(BotanECGroup::ProductionFixed());
  }
  
  TEST(BotanECGroup, Multiplication) 
  {
    AbstractGroup_Multiplication(BotanECGroup::ProductionFixed());
  }

  TEST(BotanECGroup, Exponentiation) 
  {
    AbstractGroup_Exponentiation(BotanECGroup::ProductionFixed());
  }

  TEST(BotanECGroup, Serialize)
  {
    AbstractGroup_Serialize(BotanECGroup::ProductionFixed());
  }

  TEST(BotanECGroup, Encode)
  {
    AbstractGroup_Encode(BotanECGroup::ProductionFixed());
  }

}
}
