#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(PairingGroup, Basic)
  {
    QList<QSharedPointer<PairingGroup> > list;

    list.append(QSharedPointer<PairingGroup>(PairingGroup::ProductionG1Fixed()));
    list.append(QSharedPointer<PairingGroup>(PairingGroup::ProductionGTFixed()));

    for(int i=0; i<list.count(); i++) {
      QSharedPointer<PairingGroup> group(list[i]);

      Element g = group->GetGenerator();

      ASSERT_TRUE(group->IsProbablyValid());
      ASSERT_EQ(g, g);
      ASSERT_TRUE(group->IsElement(g));
      ASSERT_FALSE(group->IsIdentity(g));
      ASSERT_TRUE(group->IsIdentity(group->Exponentiate(g, group->GetOrder())));
      ASSERT_TRUE(group->IsElement(group->Multiply(g, g)));
    }
  }

  TEST(PairingGroup, IsElement) 
  {
    QSharedPointer<PairingGroup> group = PairingGroup::ProductionG1Fixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->RandomElement()));
    }
  }

  TEST(PairingGroup, RandomExponent) 
  {
    QSharedPointer<PairingGroup> group = PairingGroup::ProductionG1Fixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->Exponentiate(group->GetGenerator(),
              group->RandomExponent())));
    }
  }

}
}
