#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(ECGroup, Basic)
  {
    QSharedPointer<ECGroup> group(ECGroup::ProductionFixed());

    Element g = group->GetGenerator();

    ASSERT_TRUE(group->IsProbablyValid());
    ASSERT_EQ(g, g);

    ASSERT_TRUE(group->IsElement(g));
    ASSERT_FALSE(group->IsIdentity(g));
    ASSERT_TRUE(group->IsIdentity(group->Exponentiate(g, group->GetOrder())));
    ASSERT_TRUE(group->IsElement(group->Exponentiate(g, group->RandomExponent())));
    ASSERT_FALSE(group->IsIdentity(group->Exponentiate(g, group->RandomExponent())));
    ASSERT_TRUE(group->IsElement(group->Multiply(g, g)));
  }

  TEST(ECGroup, IsElement) 
  {
    QSharedPointer<ECGroup> group = ECGroup::ProductionFixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->RandomElement()));
    }
  }

  TEST(ECGroup, RandomExponent) 
  {
    QSharedPointer<ECGroup> group = ECGroup::ProductionFixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(group->IsElement(group->Exponentiate(group->GetGenerator(),
              group->RandomExponent())));
    }
  }

  TEST(ECGroup, NotElement) 
  {
    QSharedPointer<ECGroup> group = ECGroup::ProductionFixed();

    int count = 0;
    for(int i=0; i<100; i++) {
      Integer x = Integer::GetRandomInteger(0, group->GetFieldSize());
      Integer y = Integer::GetRandomInteger(0, group->GetFieldSize());

      CryptoPP::ECPPoint p(CryptoPP::Integer(x.GetByteArray().constData()), 
          CryptoPP::Integer(y.GetByteArray().constData()));
      Element e(new ECElementData(p));
      if(group->IsElement(e)) count++;
    }

    EXPECT_TRUE(count < 5);
  }

}
}
