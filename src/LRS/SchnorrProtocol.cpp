
#include "SchnorrProtocol.hpp"
#include "Crypto/CryptoFactory.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  SchnorrProtocol::SchnorrProtocol(QSharedPointer<AbstractGroup> g) :
    _group(g)
  {
  }

  SchnorrProtocol::~SchnorrProtocol() {};

  void SchnorrProtocol::GenerateWitness(SigmaProof &p)
  {
    // x = random integer
    // e = g^x
    Integer x = _group->RandomExponent();
    Element e = _group->Exponentiate(_group->GetGenerator(), x);

    p.witness = IntegerToVariant(x);
    p.witness_image = ElementToVariant(e);
  };

  void SchnorrProtocol::GenerateCommit(SigmaProof &p) 
  {
    // v = random integer
    // t = g^v
    Integer v = _group->RandomExponent();
    Element t = _group->Exponentiate(_group->GetGenerator(), v);

    p.commit_secret = IntegerToVariant(v);
    p.commit = ElementToVariant(t);
  };

  void SchnorrProtocol::GenerateChallenge(SigmaProof &p) 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    // Hash group definition 
    hash->Update(_group->GetByteArray());
    hash->Update(_group->ElementToByteArray(_group->GetGenerator()));
    hash->Update(_group->ElementToByteArray(VariantToElement(p.witness_image)));
    hash->Update(_group->ElementToByteArray(VariantToElement(p.commit)));

    p.challenge = Integer(hash->ComputeHash()) % _group->GetOrder();
  }

  void SchnorrProtocol::Prove(SigmaProof &p) 
  {
    const Integer v = VariantToInteger(p.commit_secret);
    const Integer x = VariantToInteger(p.witness);

    // r = v - cx
    const Integer r = (v - (x.MultiplyMod(p.challenge, _group->GetOrder()))) % _group->GetOrder();

    p.response = IntegerToVariant(r);
  }

  void SchnorrProtocol::FakeProve(SigmaProof &p)
  {
    // pick c, r at random
    const Integer c = _group->RandomExponent();
    const Integer r = _group->RandomExponent();

    const Element w = VariantToElement(p.witness_image);

    Element t = _group->Exponentiate(w, c);
    const Element tmp = _group->Exponentiate(_group->GetGenerator(), r);
    t = _group->Multiply(tmp, t);

    // commit = (g^r) * (g^x)^c
    p.commit = ElementToVariant(t);

    // When we're fake proving, we have no commit secret and no witness
    p.commit_secret = QVariant();
    p.witness = QVariant();
  }

  bool SchnorrProtocol::Verify(SigmaProof &p) 
  {
    // g^x
    const Element e = VariantToElement(p.witness_image);
    // t = g^v
    const Element t = VariantToElement(p.commit);
    // r = v - cx
    const Integer r = VariantToInteger(p.response);
    // (g^x)^c
    Element tmp = _group->Exponentiate(e, p.challenge);

    // g^r
    Element out = _group->Exponentiate(_group->GetGenerator(), r);

    // g^{r + cx} -- should equal g^{v}
    out = _group->Multiply(tmp, out);

    // should equal g^{-v} 
    out = _group->Inverse(out);

    // should equal g^{-v} * g{v} == g^0 == 1
    out = _group->Multiply(out, t);
    return _group->IsIdentity(out);
  };

  QVariant SchnorrProtocol::IntegerToVariant(Integer i)
  {
    return QVariant(i.GetByteArray());
  }

  Integer SchnorrProtocol::VariantToInteger(QVariant v)
  {
    return Integer(v.toByteArray());
  }

  QVariant SchnorrProtocol::ElementToVariant(Element e)
  {
    return QVariant(_group->ElementToByteArray(e));
  }

  Element SchnorrProtocol::VariantToElement(QVariant v)
  {
    return _group->ElementFromByteArray(v.toByteArray());
  }
}
}
