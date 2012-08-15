#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  TEST(IntegerGroup, Basic)
  {
    IntegerGroup group(11, 5, 3);

    Element g = group.GetGenerator();

    ASSERT_TRUE(g.IsEqual(g));
    ASSERT_TRUE(group.IsValid(g));
    ASSERT_FALSE(group.IsIdentity(g));
    ASSERT_TRUE(group.IsIdentity(group.Exponentiate(g, group.GetOrder())));
    ASSERT_TRUE(group.IsValid(group.Multiply(g, g)));
  }

}
}
