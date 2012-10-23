
#include "FactorProof.hpp"
#include "Crypto/CryptoFactory.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;
using Dissent::Utils::Random;

namespace Dissent {
namespace LRS {

  FactorProof::FactorProof() :
    SigmaProof(ProofType_FactorProof),
    _witness(Integer::GetRandomInteger(DefaultModulusBits/2, true)),
    _witness_image(_witness * Integer::GetRandomInteger(DefaultModulusBits/2, true))
  {
  }

  FactorProof::FactorProof(QByteArray witness, 
          QByteArray witness_image) :
    SigmaProof(ProofType_FactorProof),
    _witness(witness),
    _witness_image(witness_image)
  {}

  FactorProof::FactorProof(QByteArray witness_image,
      QByteArray commit, 
      QByteArray challenge, 
      QByteArray response) :
    SigmaProof(ProofType_FactorProof),
    _witness_image(witness_image),
    _challenge(challenge),
    _response(response)
  {
    QDataStream stream(commit);
    stream >> _commit;
  }

  FactorProof::~FactorProof() {};

  void FactorProof::GenerateCommit()
  {
    // pick random exponent r in [0, 2^{log{n}-1})
    _commit_secret = Integer::GetRandomInteger(0, DefaultModulusBits-2, false);

    // pick K random z_i values and
    // compute x_i = z_i^r mod n
    QList<Integer> pubs = GetPublicIntegers();
    _commit.clear();
    for(int i=0; i<pubs.count(); i++) {
      _commit.append(pubs[i].Pow(_commit_secret, _witness_image));
      qDebug() << "commit[" << i << "]" << _commit[i].GetByteArray().toHex();
    }
  };

  void FactorProof::GenerateChallenge()
  {
    _challenge = CommitHash();
  }

  void FactorProof::Prove(QByteArray challenge)
  {
    if(Integer(challenge) >= BiggestChallenge()) {
      qFatal("Challenge too big");
    } 

    const Integer e = Integer::GetRandomInteger(0, BiggestChallenge(), false);
    const QByteArray e_bytes = e.GetByteArray();

    // Replace the rightmost bytes of e with the challenge
    _challenge = Integer(e_bytes.left(e_bytes.count() - challenge.count()) + challenge);

    Prove();
  }

  void FactorProof::Prove()
  {
    const Integer n = _witness_image;
    const Integer p = _witness;
    const Integer q = n / p; // n = p*q
    const Integer phi_n = (p - 1) * (q - 1);

    // response = commit_secret + ((n - phi(n)) * challenge)
    _response = (_commit_secret + ((n - phi_n) * _challenge));
  }

  void FactorProof::FakeProve()
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    Random *rnd = CryptoFactory::GetInstance().GetLibrary()->GetRandomNumberGenerator();

    QByteArray bytes(hash->GetDigestSize(), '\0');
    rnd->GenerateBlock(bytes); 

    // pick c, r at random
    _challenge = Integer::GetRandomInteger(0, BiggestChallenge(), false);
    _response = Integer::GetRandomInteger(0, DefaultModulusBits-2, false);

    const QList<Integer> pubs = GetPublicIntegers();
    _commit.clear();

    // exp = y - n*chal
    Integer exponent = _response - (_witness_image * _challenge);

    for(int i=0; i<ParallelRounds; i++) {
      Integer result;

      if(exponent >= 0) {
        result = pubs[i].Pow(exponent, _witness_image);
      } else {
        result = pubs[i].Pow(Integer(-1)* exponent, _witness_image).ModInverse(_witness_image);
      }

      _commit.append(result);
    }

    // When we're fake proving, we have no commit secret and no witness
    _commit_secret = 0;
    _witness = 0;
  }

  bool FactorProof::Verify(bool verify_challenge) const 
  {
    // response must be less than 2^{(log n) - 1}
    if(!(Integer(0) <= _response && _response < Integer(2).Pow(DefaultModulusBits-1, _witness_image))) {
      qDebug() << "Response is outside of valid range"; 
      return false;
    }

    // get public x_i values
    const QList<Integer> pubs = GetPublicIntegers();

    if(_commit.count() != pubs.count()) {
      qDebug() << "Commit and pubs have different lengths"; 
      return false;
    }

    const Integer exponent = _response - (_witness_image * _challenge);
    
    for(int i=0; i<pubs.count(); i++) {
      // x_i == z_i^{y - ne} mod n
      Integer result;
      if(exponent >= 0) {
        result = pubs[i].Pow(exponent, _witness_image);
      } else {
        // if exp < 0, return (commit^-e)^{-1} since crypto++
        // barfs on negative exponents
        result = pubs[i].Pow(Integer(-1) * exponent, _witness_image).ModInverse(_witness_image);
      }

      if(result != _commit[i]) {
        qWarning() << "Mismatched commit value caused failed proof";
        qDebug() << result.GetByteArray().toHex() << pubs[i].GetByteArray().toHex();
        return false;
      }
    }

    // if verify_challenge is set, make sure that challenge is
    // a hash of the commit 
    if(verify_challenge && _challenge != CommitHash()) {
      qDebug() << "Challenge does not match commit hash"; 
      return false;
    }

    return true;
  };

  Integer FactorProof::CommitHash() const 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    // Hash group definition 
    hash->Update(_witness_image.GetByteArray());
    for(int i=0; i<_commit.count(); i++) {
      hash->Update(_commit[i].GetByteArray());
    }

    // Value of hash mod 2^80
    return Integer(hash->ComputeHash()) % BiggestChallenge();
  }

  Integer FactorProof::BiggestChallenge() const 
  {
    return Integer(2).Pow(SoundnessParameter, _witness_image);
  }

  QList<Integer> FactorProof::GetPublicIntegers() const
  {
    QList<Integer> out;
    Random *rnd = CryptoFactory::GetInstance().GetLibrary()->
      GetRandomNumberGenerator(_witness_image.GetByteArray());

    for(int i=0; i<ParallelRounds; i++) {
      QByteArray block((_witness_image.GetByteCount()-1), '\0');
      rnd->GenerateBlock(block);
      out.append(Integer(block));

      qDebug() << "pub["<<i<<"]"<<out[i].GetByteArray().toHex();
    }

    return out;
  }

  QByteArray FactorProof::GetCommit() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << _commit;
    return out;
  }
}
}
