
#include "Crypto/CryptoFactory.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ClientCiphertext::ClientCiphertext(const Parameters params, const PublicKeySet server_pks,
      const PublicKey author_pub) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _one_time_priv(PrivateKey(_params)),
    _one_time_pub(_one_time_priv),
    _element(_server_pks.GetInteger().Pow(_one_time_priv.GetInteger(), _params.GetP())) 
  {
  }

  ClientCiphertext::ClientCiphertext(const Parameters params, const PublicKeySet server_pks,
      const PublicKey author_pub, const PublicKey one_time_pub) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _one_time_priv(_params),
    _one_time_pub(one_time_pub)
  {}

  void ClientCiphertext::SetAuthorProof(const PrivateKey &author_priv, const Plaintext &m)
  {
    _element = (_element * m.GetInteger()) % _params.GetP();

    // g1 = Product of server PKs, A = g1^a = client ciphertext elm,  a = client SK
    // g2 = DH key generator,      B = g2^b = client PK,              b = client SK
    // g3 = DH key generator,      C = g3^c = author PK,              c = author SK

    // f  = random element mod q
    // v1 = random element mod q
    // v2 = random element mod q

    Integer f, v1, v2;
    f = _params.RandomExponent();
    v1 = _params.RandomExponent();
    v2 = _params.RandomExponent();

    Integer t1, t2, t3;

    // t1 = A^f * g1^v1
    t1 = (_element.Pow(f, _params.GetP()) * 
        _server_pks.GetInteger().Pow(v1, _params.GetP())) % _params.GetP();

    // t2 = B^f * g2^v1
    t2 = (_one_time_pub.GetInteger().Pow(f, _params.GetP()) *
        _params.GetG().Pow(v1, _params.GetP())) % _params.GetP();

    // t3 = g3^v2
    t3 = _params.GetG().Pow(v2, _params.GetP());

    // chal1 = f
    _challenge_1 = f;

    // chal2 = H(g1, g2, g3, y1, y2, y3, t1, t2, t3) - f
    Integer hash = Commit(_server_pks.GetInteger(), _params.GetG(), _params.GetG(),
        _element, _one_time_pub.GetInteger(), _author_pub.GetInteger(),
        t1, t2, t3);

    _challenge_2 = (hash - f) % _params.GetQ();
   
    // resp1 = v1
    _response_1 = v1;

    // resp2 = v2 - (chal2 * c)
    _response_2 = (v2 - (_challenge_2 * author_priv.GetInteger())) % _params.GetQ();
  }

  void ClientCiphertext::SetProof()
  {
    // g1 = Product of server PKs, A = g1^a = client ciphertext elm,  a = client SK
    // g2 = DH key generator,      B = g2^b = client PK,              b = client SK
    // g3 = DH key generator,      C = g3^c = author PK,              c = author SK

    // f  = random element mod q
    // v1 = random element mod q
    // v2 = random element mod q

    Integer f, v1, v2;
    f = _params.RandomExponent();
    v1 = _params.RandomExponent();
    v2 = _params.RandomExponent();

    Integer t1, t2, t3;

    // t1 = g1^v1
    t1 = _server_pks.GetInteger().Pow(v1, _params.GetP());

    // t2 = g2^v1
    t2 = _params.GetG().Pow(v1, _params.GetP());

    // t3 = C^f * g3^v2
    t3 = (_author_pub.GetInteger().Pow(f, _params.GetP()) *
      _params.GetG().Pow(v2, _params.GetP())) % _params.GetP();

    // h = H(g1, g2, g3, y1, y2, y3, t1, t2, t3)
    // chal_1 = h - f1 (mod q)
    _challenge_1 = Commit(_server_pks.GetInteger(), _params.GetG(), _params.GetG(),
        _element, _one_time_pub.GetInteger(), _author_pub.GetInteger(),
        t1, t2, t3);
    _challenge_1 = (_challenge_1 - f) % _params.GetQ();

    // chal_2 = f
    _challenge_2 = f;

    // resp_1 = v1 - (chal_1 * a)
    _response_1 = (v1 - (_challenge_1 * _one_time_priv.GetInteger())) % _params.GetQ();

    // resp_2 = v2
    _response_2 = v2;
  }

  bool ClientCiphertext::VerifyProof() const
  {
    // g1 = Product of server PKs, A = g1^a = client ciphertext elm,  a = client SK
    // g2 = DH key generator,      B = g2^b = client PK,              b = client SK
    // g3 = DH key generator,      C = g3^c = author PK,              c = author SK

    Integer t1, t2, t3;

    // t1 = A^chal1 * g1^resp1
    t1 = (_element.Pow(_challenge_1, _params.GetP()) * 
        _server_pks.GetInteger().Pow(_response_1, _params.GetP())) % _params.GetP();

    // t2 = B^chal1 * g2^resp1
    t2 = (_one_time_pub.GetInteger().Pow(_challenge_1, _params.GetP()) * 
        _params.GetG().Pow(_response_1, _params.GetP())) % _params.GetP();

    // t3 = C^chal2 * g3^resp2
    t3 = (_author_pub.GetInteger().Pow(_challenge_2, _params.GetP()) *
        _params.GetG().Pow(_response_2, _params.GetP())) % _params.GetP();


    Integer hash = Commit(_server_pks.GetInteger(), _params.GetG(), _params.GetG(),
        _element, _one_time_pub.GetInteger(), _author_pub.GetInteger(),
        t1, t2, t3);

    Integer sum = (_challenge_1 + _challenge_2) % _params.GetQ();
    return (sum == hash);
  }

  Integer ClientCiphertext::Commit(const Integer &g1, const Integer &g2, const Integer &g3,
      const Integer &y1, const Integer &y2, const Integer &y3,
      const Integer &t1, const Integer &t2, const Integer &t3) const
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    hash->Update(_params.GetP().GetByteArray());
    hash->Update(_params.GetQ().GetByteArray());
    hash->Update(_params.GetG().GetByteArray());

    hash->Update(g1.GetByteArray());
    hash->Update(g2.GetByteArray());
    hash->Update(g3.GetByteArray());

    hash->Update(y1.GetByteArray());
    hash->Update(y2.GetByteArray());
    hash->Update(y3.GetByteArray());

    hash->Update(t1.GetByteArray());
    hash->Update(t2.GetByteArray());
    hash->Update(t3.GetByteArray());

    return Integer(hash->ComputeHash()) % _params.GetQ();
  }
}
}
}
