#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Hash.hpp"

#include "FactorProof.hpp"
#include "SchnorrProof.hpp"
#include "RingSignature.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  RingSignature::RingSignature(QList<QSharedPointer<SigmaProof> > proofs, 
      int real_idx) :
    _proofs(proofs),
    _real_idx(real_idx)
  {
    Q_ASSERT(real_idx >= 0 && real_idx < proofs.count());
  }

  RingSignature::~RingSignature() {}

  QByteArray RingSignature::Sign(const QByteArray msg) 
  {
    const int count = _proofs.count();
    QList<QByteArray> commits;
    QList<QByteArray> challenges;

    for(int i=0; i<count; i++) {
      if(i == _real_idx) {
        _proofs[i]->GenerateCommit();
      } else {
        _proofs[i]->FakeProve();
      }

      commits.append(_proofs[i]->GetCommit());
      challenges.append(_proofs[i]->GetChallenge().GetByteArray());
    }

    for(int i=0; i<count; i++) {
      _witness_images.append(_proofs[i]->GetWitnessImage());
      _proof_types.append(_proofs[i]->GetProofType());
    }

    QByteArray challenge = CreateChallenge(msg, commits);
    const int chal_len = challenge.count();

    qDebug() << "Master c" << challenge.toHex();

    // XOR all challenges together
    QByteArray final = challenge;
    for(int i=0; i<count; i++) {
      if(i == _real_idx) continue;
      QByteArray right = challenges[i].right(chal_len);
      qDebug() << "chal" << i << challenges[i].toHex();
      final = Xor(final, right); 
    }
    qDebug() << "Final c" << final.toHex();

    // The final challenge is given to the true prover

    // The final proof is then
    // commits:   t1, t2, ..., tN
    // challenge: c
    // responses: r1, r2, ..., rN

    _proofs[_real_idx]->Prove(final);

    QList<QList<QByteArray> > sig_pieces;

    sig_pieces.append(commits);

    QList<QByteArray> challenge_list;
    for(int i=0; i<count; i++) {
      challenge_list.append(_proofs[i]->GetChallenge().GetByteArray());
    }
    sig_pieces.append(challenge_list);

    QList<QByteArray> responses;
    for(int i=0; i<count; i++) {
      responses.append(_proofs[i]->GetResponse());
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
      QSharedPointer<SigmaProof> p;

      switch(_proof_types[i]) {

        case SigmaProof::ProofType_FactorProof:
          p = QSharedPointer<SigmaProof>(new FactorProof(_witness_images[i],
                commits[i], 
                challenges[i], 
                responses[i]));
          break;

        case SigmaProof::ProofType_SchnorrProof:
          p = QSharedPointer<SigmaProof>(new SchnorrProof(_witness_images[i],
                commits[i], 
                challenges[i], 
                responses[i]));
          break;


        default:
          qFatal("Unknown proof type");
      }
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
    if(challenge == test) return true;
    else {
      qDebug() << "orig" << challenge.toHex() << "found" << test.toHex();
      qDebug() << "Challenge does not match up";
      return false;
    }
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

    // We use 80-bit challenges
    return hash->ComputeHash().left(10);
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
