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

}
}
