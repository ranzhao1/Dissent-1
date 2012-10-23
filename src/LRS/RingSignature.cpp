#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Hash.hpp"

#include "SchnorrProof.hpp"
#include "RingSignature.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  RingSignature::RingSignature(QSharedPointer<AbstractGroup> group,
          QSharedPointer<SigmaProof> real, 
          QList<QSharedPointer<SigmaProof> > fakes) :
    _group(group),
    _real_proof(real),
    _fake_proofs(fakes)
  {
  }

  RingSignature::~RingSignature() {}

  QByteArray RingSignature::Sign(const QByteArray msg) 
  {
    const int count = _fake_proofs.count();
    QList<QByteArray> commits;
    QList<QByteArray> challenges;

    _real_proof->GenerateCommit();
    commits.append(_real_proof->GetCommit());

    for(int i=0; i<count; i++) {
      _fake_proofs[i]->FakeProve();
      commits.append(_fake_proofs[i]->GetCommit());
      challenges.append(_fake_proofs[i]->GetChallenge().GetByteArray());
    }

    _witness_images.append(_real_proof->GetWitnessImage());
    for(int i=0; i<count; i++) {
      _witness_images.append(_fake_proofs[i]->GetWitnessImage());
    }

    QByteArray challenge = CreateChallenge(msg, commits);
    const int chal_len = challenge.count();

    // XOR all challenges together
    QByteArray final = challenge;
    for(int i=0; i<count; i++) {
      QByteArray right = challenges[i].right(chal_len);
      final = Xor(final, right); 
    }

    // The final challenge is given to the true prover
    _real_proof->Prove(final);

    // The final proof is then
    // commits:   t1, t2, ..., tN
    // challenge: c
    // responses: r1, r2, ..., rN

    QList<QList<QByteArray> > sig_pieces;

    sig_pieces.append(commits);

    QList<QByteArray> challenge_list;
    challenge_list.append(_real_proof->GetChallenge().GetByteArray());
    for(int i=0; i<count; i++) {
      challenge_list.append(_fake_proofs[i]->GetChallenge().GetByteArray());
    }
    sig_pieces.append(challenge_list);

    QList<QByteArray> responses;
    responses.append(_real_proof->GetResponse());
    for(int i=0; i<count; i++) {
      responses.append(_fake_proofs[i]->GetResponse());
    }
    sig_pieces.append(responses);

    QByteArray sig;
    QDataStream stream(&sig, QIODevice::WriteOnly);
    stream << sig_pieces;

    return sig;
  }

  bool RingSignature::Verify(const QByteArray msg, const QByteArray sig) 
  {
    QList<QList<QByteArray> > sig_pieces;
    QDataStream stream(sig);
    stream >> sig_pieces;
    
    if(sig_pieces.count() != 3) {
      qWarning() << "sig_pieces has wrong length";
      return false;
    }

    QList<QByteArray> commits = sig_pieces[0];
    QList<QByteArray> challenges = sig_pieces[1];
    QList<QByteArray> responses = sig_pieces[2];

    if(_witness_images.count() != responses.count()) {
      qWarning() << "_witness_images.count() != responses.count()";
      return false;
    }

    if(commits.count() != responses.count()) {
      qWarning() << "commits.count() != responses.count()";
      return false;
    }

    if(commits.count() != challenges.count()) {
      qWarning() << "commits.count() != challenges.count()";
      return false;
    }

    QList<QSharedPointer<SigmaProof> > proofs;

    // unserialize the protocols
    for(int i=0; i<commits.count(); i++) {
      QSharedPointer<SigmaProof> p(new SchnorrProof(_group, 
            _witness_images[i],
            commits[i], 
            challenges[i], 
            responses[i]));
      if(!p->Verify(false)) {
        qDebug() << "Proof" << i << "was invalid";
        return false;
      }
    }

    // Compute hash of all commits
    QByteArray challenge = CreateChallenge(msg, commits);

    const int chal_len = challenge.count();

    // Compute XOR of all challenges' rightmost bytes
    QByteArray test(chal_len, '\0');
    for(int i=0; i<challenges.count(); i++) {
      test = Xor(test, challenges[i].right(chal_len));
    }

    // Check that hash matches XOR
    return (challenge == test);
  }

  QByteArray RingSignature::CreateChallenge(const QByteArray &msg, const QList<QByteArray> &commits) const
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();

    // Note that this construction is unsafe since the
    // values (a, b, c) and (abc, "", "") might hash to the
    // same value. This is just a prototype, so we can
    // use a more robust hashing construction if we need to
    // make this code production-ready.
    hash->Restart();
    hash->Update(msg);
    for(int i=0; i<commits.count(); i++) {
      hash->Update(commits[i]);
    }

    return hash->ComputeHash();
  }

  QByteArray RingSignature::Xor(const QByteArray &a, const QByteArray &b) const
  {
    Q_ASSERT(a.count() == b.count());
    QByteArray out(a.count(), '\0');
 
    for(int i=0; i<a.count(); i++) {
      out[i] = a[i] ^ b[i];
    }

    return out;
  }

}
}
