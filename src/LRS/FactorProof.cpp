
#include "FactorProof.hpp"
#include "Crypto/CryptoFactory.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  FactorProof::FactorProof() :
    SigmaProof(),
    _witness(Integer::GetRandomInteger(DefaultModulusBits/2, true)),
    _witness_image(_witness * Integer::GetRandomInteger(DefaultModulusBits/2, true))
  {
  }

  FactorProof::FactorProof(QByteArray witness, 
          QByteArray witness_image) :
    _witness(witness),
    _witness_image(witness_image)
  {}

  FactorProof::FactorProof(QByteArray witness_image,
      QByteArray commit, 
      QByteArray challenge, 
      QByteArray response) :
    SigmaProof(),
    _witness_image(witness_image),
    _commit(commit),
    _challenge(challenge),
    _response(response)
  {
  }

  FactorProof::~FactorProof() {};

  void FactorProof::GenerateCommit()
  {
    // pick random exponent r in [0, 2^log{n})
    _commit_secret = Integer::GetRandomInteger(0, DefaultModulusBits-1, false);

    // pick K random z_i values and
    // compute x_i = z_i^r mod n
    for(int i=0; i<ParallelRounds; i++) {
      _commit.append(Integer::GetRandomInteger(1, _witness_image-1).Pow();
    }


    _commit = _group->Exponentiate(_group->GetGenerator(), _commit_secret);
  };

  void FactorProof::GenerateChallenge()
  {
    _challenge = CommitHash();
  }

  void FactorProof::Prove()
  {
    Prove(_challenge);
  }

  void FactorProof::Prove(QByteArray challenge)
  {
    const Integer e = _group->RandomExponent();
    const QByteArray e_bytes = e.GetByteArray();
    const int e_orig_len = e_bytes.count();

    if(e_bytes.count() <= challenge.count())
      qFatal("Challenge is bigger than group order");

    // Replace the rightmost bytes of e with the challenge
    const QByteArray final = e_bytes.left(e_bytes.count() - challenge.count()) + challenge;

    Q_ASSERT(e_orig_len == final.count());

    return Prove(Integer("0x" + final));  
  }

  void FactorProof::Prove(Integer challenge)
  {
    _challenge = challenge;

    // r = v - cx
    _response = (_commit_secret - (_witness.MultiplyMod(challenge, _group->GetOrder()))) % _group->GetOrder();
  }

  void FactorProof::FakeProve()
  {
    // pick c, r at random
    _challenge = _group->RandomExponent();
    _response = _group->RandomExponent();

    _commit = _group->Exponentiate(_witness_image, _challenge);
    const Element tmp = _group->Exponentiate(_group->GetGenerator(), _response);
    // commit = (g^r) * (g^x)^c
    _commit = _group->Multiply(tmp, _commit);

    // When we're fake proving, we have no commit secret and no witness
    _commit_secret = 0;
    _witness = 0;
  }

  bool FactorProof::Verify(bool verify_challenge) const 
  {
    // (g^x)^c
    Element tmp = _group->Exponentiate(_witness_image, _challenge);

    // g^r
    Element out = _group->Exponentiate(_group->GetGenerator(), _response);

    // g^{r + cx} -- should equal g^{v}
    out = _group->Multiply(tmp, out);

    // should equal g^{-v} 
    out = _group->Inverse(out);

    // should equal g^{-v} * g{v} == g^0 == 1
    out = _group->Multiply(out, _commit);

    // check hash
    Integer test;

    bool valid = _group->IsIdentity(out);
    // if verify_challenge is set, make sure that challenge is
    // a hash of the commit 
    if(verify_challenge) 
      valid = valid && (_challenge == CommitHash());

    return valid;
  };

  QVariant FactorProof::ElementToVariant(Element e) const
  {
    return QVariant(_group->ElementToByteArray(e));
  }

  Element FactorProof::VariantToElement(QVariant v) const
  {
    return _group->ElementFromByteArray(v.toByteArray());
  }

  Integer FactorProof::CommitHash() const 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    // Hash group definition 
    hash->Update(_group->GetByteArray());
    hash->Update(_group->ElementToByteArray(_group->GetGenerator()));
    hash->Update(_group->ElementToByteArray(_witness_image));
    hash->Update(_group->ElementToByteArray(_commit));

    return Integer(hash->ComputeHash()) % _group->GetOrder();
  }

  QList<Integer> FactorProof::GetPublicIntegers() const
  {
    QList<Integer> out;

    return out;
  }

}
}
