#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class LRSProofTest : 
    public ::testing::TestWithParam<QSharedPointer<AbstractGroup::AbstractGroup> > {
  };

  TEST_P(LRSProofTest, SchnorrProve)
  {
    //SchnorrProof proto(GetParam());
    SchnorrProof proto;

    for(int i=0; i<500; i++) {
      proto.GenerateCommit();
      proto.GenerateChallenge();
      proto.Prove();

      EXPECT_TRUE(proto.Verify());
    }
  }

  TEST_P(LRSProofTest, SchnorrProveFake)
  {
    //SchnorrProof proto(GetParam());
    SchnorrProof proto;

    for(int i=0; i<500; i++) {
      proto.SetWitness(0); 

      proto.FakeProve();
      EXPECT_TRUE(proto.Verify(false));
    }
  }

  TEST_P(LRSProofTest, SchnorrRing)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    for(int repeat=0; repeat<50; repeat++) {
      int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int author_idx = Random::GetInstance().GetInt(0, count);
   
      QList<QSharedPointer<SigmaProof> > list;
      for(int j=0; j<count; j++) {
        list.append(QSharedPointer<SigmaProof>(new SchnorrProof()));
      }

      QByteArray msg(1024, '\0');
      rand->GenerateBlock(msg);

      RingSignature ring(list, author_idx);

      QByteArray sig = ring.Sign(msg);
      EXPECT_TRUE(ring.Verify(msg, sig));

      // Tweak one byte of the message
      msg[3] = !msg[3];
      EXPECT_FALSE(ring.Verify(msg, sig));
    }
  }

  INSTANTIATE_TEST_CASE_P(LRS, LRSProofTest,
      ::testing::Values(
        IntegerGroup::GetGroup(IntegerGroup::TESTING_512),
        CppECGroup::GetGroup(ECParams::NIST_P192),
        OpenECGroup::GetGroup(ECParams::NIST_P192),
        BotanECGroup::GetGroup(ECParams::NIST_P192)));

  TEST(LRSProofTest, FactorProve)
  {
    FactorProof proof;
    for(int i=0; i<20; i++) {
      proof.GenerateCommit();
      proof.GenerateChallenge();
      proof.Prove();

      EXPECT_TRUE(proof.Verify());
    }
  }

  TEST(LRSProofTest, FactorProveFake)
  {
    FactorProof proto;

    for(int i=0; i<20; i++) {
      proto.SetWitness(0); 

      proto.FakeProve();
      EXPECT_TRUE(proto.Verify(false));
    }
  }

  TEST(LRSProofTest, FactorRing)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    for(int repeat=0; repeat<50; repeat++) {
      int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int author_idx = Random::GetInstance().GetInt(0, count);
   
      QList<QSharedPointer<SigmaProof> > list;
      for(int j=0; j<count; j++) {
        list.append(QSharedPointer<SigmaProof>(new FactorProof()));
      }

      QByteArray msg(1024, '\0');
      rand->GenerateBlock(msg);

      RingSignature ring(list, author_idx);

      QByteArray sig = ring.Sign(msg);
      EXPECT_TRUE(ring.Verify(msg, sig));

      // Tweak one byte of the message
      msg[3] = !msg[3];
      EXPECT_FALSE(ring.Verify(msg, sig));
    }
  }

}
}

