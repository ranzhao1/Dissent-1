#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(IntegerGroup, Basic)
  {
    QList<QSharedPointer<IntegerGroup> > list;

    list.append(QSharedPointer<IntegerGroup>(new IntegerGroup(11, 3)));
    list.append(QSharedPointer<IntegerGroup>(IntegerGroup::TestingFixed()));
    list.append(QSharedPointer<IntegerGroup>(IntegerGroup::Production1024Fixed()));
    list.append(QSharedPointer<IntegerGroup>(IntegerGroup::Production2048Fixed()));

    for(int i=0; i<list.count(); i++) {
      QSharedPointer<IntegerGroup> group(list[i]);

      Element g = group->GetGenerator();

      ASSERT_TRUE(group->IsProbablyValid());
      ASSERT_EQ(g, g);
      ASSERT_TRUE(group->IsElement(g));
      ASSERT_FALSE(group->IsIdentity(g));
      ASSERT_TRUE(group->IsIdentity(group->Exponentiate(g, group->GetOrder())));
      ASSERT_TRUE(group->IsElement(group->Multiply(g, g)));
    }
  }

  TEST(IntegerGroup, IsElement) 
  {
    QSharedPointer<IntegerGroup> group = IntegerGroup::TestingFixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->RandomElement()));
    }
  }

  TEST(IntegerGroup, RandomExponent) 
  {
    QSharedPointer<IntegerGroup> group = IntegerGroup::TestingFixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->Exponentiate(group->GetGenerator(),
              group->RandomExponent())));
    }
  }

  TEST(IntegerGroup, NotElement) 
  {
    QSharedPointer<IntegerGroup> group = IntegerGroup::TestingFixed();

    int count = 0;
    for(int i=0; i<100; i++) {
      Element e(new IntegerElementData(Integer::GetRandomInteger(0, group->GetModulus())));
      if(group->IsElement(e)) count++;
    }

    EXPECT_TRUE(count > 30 && count < 70);
  }

}
}
