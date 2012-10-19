#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class LRSProofTest : 
    public ::testing::TestWithParam<QSharedPointer<AbstractGroup::AbstractGroup> > {
  };

  TEST_P(LRSProofTest, SchnorrProve)
  {
    SchnorrProtocol proto(GetParam());

    for(int i=0; i<500; i++) {
      SigmaProtocol::SigmaProof proof;
      proto.GenerateWitness(proof);
      proto.GenerateCommit(proof);
      proto.GenerateChallenge(proof);
      proto.Prove(proof);

      EXPECT_TRUE(proto.Verify(proof));
    }
  }

  TEST_P(LRSProofTest, SchnorrProveFake)
  {
    SchnorrProtocol proto(GetParam());

    for(int i=0; i<500; i++) {
      SigmaProtocol::SigmaProof proof;
      proto.GenerateWitness(proof);

      proof.witness = QVariant();

      // for FakeProve we have no witness
      // and no commit secret
      EXPECT_EQ(QVariant(), proof.commit_secret);

      proto.FakeProve(proof);
      EXPECT_TRUE(proto.Verify(proof));
    }
  }

  INSTANTIATE_TEST_CASE_P(LRS, LRSProofTest,
      ::testing::Values(
        IntegerGroup::GetGroup(IntegerGroup::TESTING_512),
        CppECGroup::GetGroup(ECParams::NIST_P192),
        OpenECGroup::GetGroup(ECParams::NIST_P192),
        BotanECGroup::GetGroup(ECParams::NIST_P192)));

}
}

