
#include "Crypto/AbstractGroup/CppECGroup.hpp"
#include "Crypto/AbstractGroup/ECParams.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "SchnorrProof.hpp"

using Dissent::Crypto::AbstractGroup::CppECGroup;
using Dissent::Crypto::AbstractGroup::ECParams;
using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  SchnorrProof::SchnorrProof() :
    SigmaProof(ProofType_SchnorrProof),
    _group(CppECGroup::GetGroup(ECParams::NIST_P192)),
    _witness(_group->RandomExponent()),
    _witness_image(_group->Exponentiate(_group->GetGenerator(), _witness))
  {
  }

  SchnorrProof::SchnorrProof(QByteArray witness, 
          QByteArray witness_image) :
    SigmaProof(ProofType_SchnorrProof),
    _group(CppECGroup::GetGroup(ECParams::NIST_P192)),
    _witness(witness),
    _witness_image(_group->ElementFromByteArray(witness_image))
  {}

  SchnorrProof::SchnorrProof(QByteArray witness_image,
      QByteArray commit, 
      QByteArray challenge, 
      QByteArray response) :
    SigmaProof(ProofType_SchnorrProof),
    _group(CppECGroup::GetGroup(ECParams::NIST_P192)),
    _witness_image(_group->ElementFromByteArray(witness_image)),
    _commit(_group->ElementFromByteArray(commit)),
    _challenge(challenge),
    _response(response)
  {
  }

  SchnorrProof::~SchnorrProof() {};

  void SchnorrProof::GenerateCommit()
  {
    // v = random integer
    // t = g^v
    _commit_secret = _group->RandomExponent();
    _commit = _group->Exponentiate(_group->GetGenerator(), _commit_secret);
  };

  void SchnorrProof::GenerateChallenge()
  {
    _challenge = CommitHash();
  }

  void SchnorrProof::Prove(QByteArray challenge)
  {
    const Integer e = _group->RandomExponent();
    const QByteArray e_bytes = e.GetByteArray();
    const int e_orig_len = e_bytes.count();

    if(e_bytes.count() <= challenge.count())
      qFatal("Challenge is bigger than group order");

    // Replace the rightmost bytes of e with the challenge
    const QByteArray final = e_bytes.left(e_bytes.count() - challenge.count()) + challenge;

    Q_ASSERT(e_orig_len == final.count());

    _challenge = Integer(final);  
  }

  void SchnorrProof::Prove()
  {
    // r = v - cx
    _response = (_commit_secret - (_witness.MultiplyMod(_challenge, _group->GetOrder()))) % _group->GetOrder();
  }

  void SchnorrProof::FakeProve()
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

  bool SchnorrProof::Verify(bool verify_challenge) const 
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

  Integer SchnorrProof::CommitHash() const 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    // Hash group definition 
    hash->Update(_group->GetByteArray());
    hash->Update(_group->ElementToByteArray(_group->GetGenerator()));
    hash->Update(_group->ElementToByteArray(_witness_image));
    hash->Update(_group->ElementToByteArray(_commit));

    qDebug() << "g" << _group->ElementToByteArray(_group->GetGenerator()).toHex();
    qDebug() << "wi" << _group->ElementToByteArray(_witness_image).toHex();
    qDebug() << "commit" << _group->ElementToByteArray(_commit).toHex();

    return Integer(hash->ComputeHash()) % _group->GetOrder();
  }
}
}
