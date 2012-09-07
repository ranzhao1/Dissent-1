#include "AbstractGroupHelpers.hpp"
#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class IntegerGroupTest : 
    public ::testing::TestWithParam<int> {
  };

  TEST_P(IntegerGroupTest, Basic)
  {
    const QSharedPointer<IntegerGroup> group = IntegerGroup::GetGroup((IntegerGroup::GroupSize)GetParam());
    AbstractGroup_Basic(group);
  }

  TEST_P(IntegerGroupTest, RandomExponent)
  {
    const QSharedPointer<IntegerGroup> group = IntegerGroup::GetGroup((IntegerGroup::GroupSize)GetParam());
    AbstractGroup_RandomExponent(group);
  }

  TEST_P(IntegerGroupTest, NotElement) 
  {
    const QSharedPointer<IntegerGroup> group = IntegerGroup::GetGroup((IntegerGroup::GroupSize)GetParam());

    int count = 0;
    for(int i=0; i<100; i++) {
      Element e(new IntegerElementData(Integer::GetRandomInteger(0, group->GetModulus())));
      if(group->IsElement(e)) count++;
    }

    EXPECT_TRUE(count > 30 && count < 70);
  }

  TEST_P(IntegerGroupTest, Serialize)
  {
    const QSharedPointer<IntegerGroup> group = IntegerGroup::GetGroup((IntegerGroup::GroupSize)GetParam());
    AbstractGroup_Serialize(group);
  }

  TEST_P(IntegerGroupTest, Encode)
  {
    const QSharedPointer<IntegerGroup> group = IntegerGroup::GetGroup((IntegerGroup::GroupSize)GetParam());
    AbstractGroup_Encode(group);
  }

  INSTANTIATE_TEST_CASE_P(IntegerGroup, IntegerGroupTest,
      ::testing::Range(0, (int)IntegerGroup::INVALID));

}
}
