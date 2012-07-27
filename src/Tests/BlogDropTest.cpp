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

  TEST(BlogDrop, PlaintextEmpty) {
    Parameters params = Parameters::Parameters::Fixed();
    Plaintext p(params);
    EXPECT_EQ(QByteArray(), p.Decode());
  }

  TEST(BlogDrop, PlaintextShort) {
    Parameters params = Parameters::Parameters::Fixed();
    Plaintext p(params);

    QByteArray shorts("shorts");
    EXPECT_EQ(QByteArray(), p.Encode(shorts));
    EXPECT_EQ(shorts, p.Decode());
  }

  TEST(BlogDrop, PlaintextRandom) {
    Parameters params = Parameters::Parameters::Fixed();
    Plaintext p(params);

    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    QByteArray msg(2048, 0);
    rand->GenerateBlock(msg);

    QByteArray leftover = p.Encode(msg);
    EXPECT_TRUE(leftover.count() < msg.count());

    QByteArray output = p.Decode();
    EXPECT_TRUE(output.count() > 0);
    EXPECT_TRUE(output.count() < params.GetP().GetByteCount());
    EXPECT_TRUE(output.count() > (params.GetP().GetByteCount()-4));
    EXPECT_EQ(msg, output+leftover);
  }
}
}
