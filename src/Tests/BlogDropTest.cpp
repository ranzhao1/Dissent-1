#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(BlogDrop, ParamsFixed) {
    Parameters params = Parameters::Parameters::Fixed();

    EXPECT_EQ(Integer(1), params.GetG().Pow(params.GetQ(), params.GetP()));
  }

  TEST(BlogDrop, ParamsIsElement) {
    Parameters params = Parameters::Parameters::Fixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(params.IsElement(params.RandomElement()));
    }
  }

  TEST(BlogDrop, ParamsRandomExponent) {
    Parameters params = Parameters::Parameters::Fixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(params.IsElement(params.GetG().Pow(
              params.RandomExponent(), params.GetP())));
    }
  }

  TEST(BlogDrop, ParamsNotElement) {
    Parameters params = Parameters::Parameters::Fixed();

    int count = 0;
    for(int i=0; i<100; i++) {
      if(params.IsElement(Integer::GetRandomInteger(0, params.GetP()))) count++;
    }

    EXPECT_TRUE(count > 30 && count < 70);
  }
}
}
