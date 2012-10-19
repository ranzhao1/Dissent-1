
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include "GQProtocol.hpp"
#include "Crypto/CppIntegerData.hpp"
#include "Crypto/CryptoFactory.hpp"

using Dissent::Crypto::CppIntegerData;
using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  /**
   * Implementation of the Guillou-Quisquater identification protocol
   */

  GQProtocol::GQProtocol()
  {
  }

  GQProtocol::~GQProtocol() {};

  void GQProtocol::GenerateWitness(SigmaProof &p)
  {
    CryptoPP::AutoSeededX917RNG<CryptoPP::AES()> rng;
    CryptoPP::InvertibleRSAFunction priv;
    priv.Initialize(rng, modulus_bits);

    const Integer y(prover_y);

    const Integer e(new CppIntegerData(priv.GetPublicExponent()));
    const Integer d(new CppIntegerData(priv.GetPrivateExponent()));
    const Integer n(new CppIntegerData(priv.GetModulus()));

    // x = y^{1/e} mod n
    const Integer x = y.Pow(d, n);

    // witness is (x, d)
    QList<QVariant> private_l;
    private_l.append(x.GetByteArray());
    private_l.append(d.GetByteArray());
    p.witness = QVariant(private_l);

    // witness image is (n, e)
    QList<QVariant> public_l;
    public_l.append(n.GetByteArray());
    public_l.append(e.GetByteArray());
    p.witness_image = QVariant(public_l);
  };

  void GQProtocol::GenerateCommit(SigmaProof &p) 
  {
    // get pair (n, e)
    QList<QVariant> public_l(p.witness_image.toList());

    Integer n = 0, e = 0;
    if(public_l.count() == 2) {
      n = Integer(public_l[0].toByteArray());
      e = Integer(public_l[1].toByteArray());
    } 

    // commit is t = v^e mod n, for a random value v
    const Integer v(Integer::GetRandomInteger(0, n-1, false));
    const Integer t = v.Pow(e, n);

    p.commit = IntegerToVariant(t);
    p.commit_secret = IntegerToVariant(v);
  };

  void GQProtocol::GenerateChallenge(SigmaProof &p) 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    QList<QVariant> public_l(p.witness.toList());

    Integer n = 0, e = 0;
    if(public_l.count() == 2) {
      n = Integer(public_l[0].toByteArray());
      e = Integer(public_l[1].toByteArray());
    }

    // Hash group definition 
    hash->Update(n.GetByteArray());
    hash->Update(e.GetByteArray());
    hash->Update(VariantToInteger(p.commit).GetByteArray());

    p.challenge = Integer(hash->ComputeHash()) % _group->GetOrder();
  }

  void GQProtocol::Prove(SigmaProof &p) 
  {
    // witness is (x, d)
    QPair<QByteArray, QByteArray> secret_pair(p.witness.toPair());
    const Integer x(secret_pair.first);
    const Integer d(secret_pair.second);

    QPair<QByteArray, QByteArray> public_pair(p.witness_image.toPair());
    const Integer n(public_pair.first);
    const Integer e(public_pair.second);

    // r = t * (x^c)
    const Integer out = x.Pow(p.challenge, n);
    p.response = VariantToInteger(p.commit).MultiplyMod(out, n);
  }

  void GQProtocol::FakeProve(SigmaProof &p)
  {
    QPair<QByteArray, QByteArray> public_pair(p.witness_image.toPair());
    const Integer n(public_pair.first);
    const Integer e(public_pair.second);

    // pick random r and c
    const Integer r(Integer::GetRandomInteger(0, Integer(n.GetByteArray())-1, false));
    const Integer c(Integer::GetRandomInteger(0, Integer(n.GetByteArray())-1, false));

    const Integer y(prover_y);

    // commit = (r^e)((y^c)^{-1})
   
    // first = r^e 
    const Integer first = r.Pow(e, n);

    // y^c mod n
    Integer out = y.Pow(c, n);
    // (y^c)^{-1}
    out = out.ModInverse(n);
    // (r^e)(y^c)^{-1}
    out = first.MultiplyMod(out, n);
  
    p.commit = IntegerToVariant(out);
    p.response = IntegerToVariant(r);
    p.challenge = c;
  }

  bool GQProtocol::Verify(SigmaProof &p) 
  {
    return false;
  }

}
}
