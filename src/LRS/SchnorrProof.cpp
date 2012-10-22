
#include "SchnorrProof.hpp"
#include "Crypto/CryptoFactory.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  SchnorrProof::SchnorrProof(QSharedPointer<AbstractGroup> g) :
    SigmaProof(),
    _group(g)
  {
  }

  SchnorrProof::~SchnorrProof() {};

  void SchnorrProof::GenerateWitness()
  {
    // x = random integer
    // e = g^x
    _witness = _group->RandomExponent();
    _witness_image = _group->Exponentiate(_group->GetGenerator(), _witness);
  };

  void SchnorrProof::GenerateCommit()
  {
    // v = random integer
    // t = g^v
    _commit_secret = _group->RandomExponent();
    _commit = _group->Exponentiate(_group->GetGenerator(), _commit_secret);
  };

  void SchnorrProof::GenerateChallenge()
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    // Hash group definition 
    hash->Update(_group->GetByteArray());
    hash->Update(_group->ElementToByteArray(_group->GetGenerator()));
    hash->Update(_group->ElementToByteArray(_witness_image));
    hash->Update(_group->ElementToByteArray(_commit));

    _challenge = Integer(hash->ComputeHash()) % _group->GetOrder();
  }

  void SchnorrProof::Prove()
  {
    Prove(_group->RandomExponent());
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

    return Prove(Integer("0x" + final));  
  }

  void SchnorrProof::Prove(Integer challenge)
  {
    _challenge = challenge;

    // r = v - cx
    _response = (_commit_secret - (_witness.MultiplyMod(challenge, _group->GetOrder()))) % _group->GetOrder();
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

  bool SchnorrProof::Verify() const 
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
    return _group->IsIdentity(out);
  };

  QVariant SchnorrProof::ElementToVariant(Element e) const
  {
    return QVariant(_group->ElementToByteArray(e));
  }

  Element SchnorrProof::VariantToElement(QVariant v) const
  {
    return _group->ElementFromByteArray(v.toByteArray());
  }
}
}
