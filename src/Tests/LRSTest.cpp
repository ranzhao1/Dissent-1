#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class LRSProofTest : 
    public ::testing::TestWithParam<QSharedPointer<AbstractGroup::AbstractGroup> > {
  };

  TEST_P(LRSProofTest, SchnorrProve)
  {
    SchnorrProof proto(GetParam());

    for(int i=0; i<500; i++) {
      proto.GenerateWitness();
      proto.GenerateCommit();
      proto.GenerateChallenge();
      proto.Prove();

      EXPECT_TRUE(proto.Verify());
    }
  }

  TEST_P(LRSProofTest, SchnorrProveFake)
  {
    SchnorrProof proto(GetParam());

    for(int i=0; i<500; i++) {
      proto.GenerateWitness();

      proto.SetWitness(0); 

      proto.FakeProve();
      EXPECT_TRUE(proto.Verify());
    }
  }

  QByteArray Xor(const QByteArray &a, const QByteArray &b)
  {
    Q_ASSERT(a.count() == b.count());
    QByteArray out(a.count(), '\0');
 
    for(int i=0; i<a.count(); i++) {
      out[i] = a[i] ^ b[i];
    }

    return out;
  }

  TEST_P(LRSProofTest, SchnorrRing)
  {
    for(int i=0; i<500; i++) {
      int count = 1;//Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int sender = 0;//Random::GetInstance().GetInt(0, count);
   
      QList<SchnorrProof> list;
      QList<QByteArray> commits;
      for(int j=0; j<count; j++) {
        list.append(SchnorrProof(GetParam()));
        list[j].GenerateWitness();
        if(j == sender) {
          list[j].GenerateCommit();
        } else {
          list[j].FakeProve();
        }

        commits.append(list[i].GetCommit());
      }

      QByteArray challenge = SigmaProof::CreateChallenge(commits);
      const int commit_len = challenge.count();

      // XOR all challenges together
      QByteArray final = challenge;
      for(int j=0; j<count; j++) {
        QByteArray right = commits[j].right(commit_len);
        qDebug() << "final" << final.count() << "right" << right.count();
        final = Xor(final, right); 
      }

      // The final challenge is given to the true prover
      list[sender].Prove(final);

      for(int j=0; j<count; j++) {
        EXPECT_TRUE(list[j].Verify());
      }

      QByteArray verif_final(commit_len, '\0');
      for(int j=0; j<count; j++) {
        verif_final = Xor(verif_final, list[j].GetCommit().right(commit_len));
      }

      EXPECT_EQ(challenge, verif_final);
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

