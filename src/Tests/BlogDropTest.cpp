#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(BlogDrop, ParamsFixed) 
  {
    Parameters params = Parameters::Parameters::Fixed();

    EXPECT_EQ(Integer(1), params.GetG().Pow(params.GetQ(), params.GetP()));
  }

  TEST(BlogDrop, ParamsIsElement) 
  {
    Parameters params = Parameters::Parameters::Fixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(params.IsElement(params.RandomElement()));
    }
  }

  TEST(BlogDrop, ParamsRandomExponent) 
  {
    Parameters params = Parameters::Parameters::Fixed();

    for(int i=0; i<100; i++) {
      EXPECT_TRUE(params.IsElement(params.GetG().Pow(
              params.RandomExponent(), params.GetP())));
    }
  }

  TEST(BlogDrop, ParamsNotElement) 
  {
    Parameters params = Parameters::Parameters::Fixed();

    int count = 0;
    for(int i=0; i<100; i++) {
      if(params.IsElement(Integer::GetRandomInteger(0, params.GetP()))) count++;
    }

    EXPECT_TRUE(count > 30 && count < 70);
  }

  TEST(BlogDrop, PlaintextEmpty) 
  {
    Parameters params = Parameters::Parameters::Fixed();
    Plaintext p(params);
    EXPECT_EQ(QByteArray(), p.Decode());
  }

  TEST(BlogDrop, PlaintextShort) 
  {
    Parameters params = Parameters::Parameters::Fixed();
    Plaintext p(params);

    QByteArray shorts("shorts");
    EXPECT_EQ(QByteArray(), p.Encode(shorts));
    EXPECT_EQ(shorts, p.Decode());
  }

  TEST(BlogDrop, PlaintextRandom) 
  {
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

  TEST(BlogDrop, Keys) 
  {
    Parameters params = Parameters::Parameters::Fixed();

    PrivateKey priv(params);
    Integer x = priv.GetInteger();

    PublicKey pub(priv);
    Integer gx = pub.GetInteger();

    ASSERT_TRUE(x < params.GetQ());
    ASSERT_TRUE(x > 0);
    ASSERT_TRUE(gx < params.GetP());
    ASSERT_TRUE(gx > 0);
    ASSERT_EQ(gx, params.GetG().Pow(x, params.GetP()));
  }

  TEST(BlogDrop, PublicKeySet) 
  {
    const int nkeys = 100;
    Parameters params = Parameters::Parameters::Fixed();

    QSet<PublicKey> keys;
    Integer prod = 1;
    for(int i=0; i<nkeys; i++) {
      PrivateKey priv(params);
      PublicKey pub(priv);
      keys.insert(pub);

      prod = (prod * pub.GetInteger()) % params.GetP();
    }

    PublicKeySet keyset(params, keys);
    ASSERT_EQ(prod, keyset.GetInteger());
  }

  TEST(BlogDrop, ServerCiphertext) 
  {
    for(int t=0; t<10; t++) {
      const int nkeys = 100;
      Parameters params = Parameters::Parameters::Fixed();

      QSet<PublicKey> client_pks;
      for(int i=0; i<nkeys; i++) {
        PrivateKey priv(params);
        PublicKey pub(priv);
        client_pks.insert(pub);
      }

      PublicKeySet client_pk_set(params, client_pks);

      PrivateKey server_sk(params);
      ServerCiphertext c(params, client_pk_set);
      c.SetProof(server_sk);

      Integer expected = client_pk_set.GetInteger().Pow(server_sk.GetInteger(), params.GetP()).ModInverse(params.GetP());
      ASSERT_EQ(expected, c.GetElement());

      ASSERT_TRUE(c.VerifyProof(PublicKey(server_sk)));
    }
  }
}
}
