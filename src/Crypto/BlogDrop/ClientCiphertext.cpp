
#include <QtCore>
#include "Crypto/CryptoFactory.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _one_time_priv(new PrivateKey(_params)),
    _one_time_pub(new PublicKey(_one_time_priv)),
    _element(_server_pks->GetInteger().Pow(_one_time_priv->GetInteger(), _params->GetP())) 
  {
  }

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub)
  {
    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    if(list.count() != 6) {
      qWarning() << "Failed to unserialize";
      return; 
    }

    _one_time_pub = QSharedPointer<const PublicKey>(new PublicKey(params, Integer(list[0])));
    _element = Integer(list[1]);
    _challenge_1 = Integer(list[2]);
    _challenge_2 = Integer(list[3]);
    _response_1 = Integer(list[4]);
    _response_2 = Integer(list[5]);
  }

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QSharedPointer<const PublicKey> one_time_pub) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _one_time_priv(new PrivateKey(_params)),
    _one_time_pub(one_time_pub)
  {}

  void ClientCiphertext::SetAuthorProof(const QSharedPointer<const PrivateKey> author_priv, const Plaintext &m)
  {
    _element = _element.MultiplyMod(m.GetInteger(), _params->GetP());

    // g1 = Product of server PKs, A = g1^a = client ciphertext elm,  a = client SK
    // g2 = DH key generator,      B = g2^b = client PK,              b = client SK
    // g3 = DH key generator,      C = g3^c = author PK,              c = author SK

    // f  = random element mod q
    // v1 = random element mod q
    // v2 = random element mod q

    Integer f, v1, v2;
    f = _params->RandomExponent();
    v1 = _params->RandomExponent();
    v2 = _params->RandomExponent();

    Integer t1, t2, t3;

    // t1 = A^f * g1^v1
    t1 = _params->GetP().PowCascade(_element, f, _server_pks->GetInteger(), v1);

    // t2 = B^f * g2^v1
    t2 = _params->GetP().PowCascade(_one_time_pub->GetInteger(), f, 
        _params->GetG(), v1);

    // t3 = g3^v2
    t3 = _params->GetG().Pow(v2, _params->GetP());

    // chal1 = f
    _challenge_1 = f;

    // chal2 = H(g1, g2, g3, y1, y2, y3, t1, t2, t3) - f
    Integer hash = Commit(_server_pks->GetInteger(), _params->GetG(), _params->GetG(),
        _element, _one_time_pub->GetInteger(), _author_pub->GetInteger(),
        t1, t2, t3);

    _challenge_2 = (hash - f) % _params->GetQ();
   
    // resp1 = v1
    _response_1 = v1;

    // resp2 = v2 - (chal2 * c)
    _response_2 = (v2 - (_challenge_2.MultiplyMod(author_priv->GetInteger(), 
            _params->GetQ()))) % _params->GetQ();
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
    f = _params->RandomExponent();
    v1 = _params->RandomExponent();
    v2 = _params->RandomExponent();

    Integer t1, t2, t3;

    // t1 = g1^v1
    t1 = _server_pks->GetInteger().Pow(v1, _params->GetP());

    // t2 = g2^v1
    t2 = _params->GetG().Pow(v1, _params->GetP());

    // t3 = C^f * g3^v2
    t3 = _params->GetP().PowCascade(_author_pub->GetInteger(), f, 
      _params->GetG(), v2);

    // h = H(g1, g2, g3, y1, y2, y3, t1, t2, t3)
    // chal_1 = h - f1 (mod q)
    _challenge_1 = Commit(_server_pks->GetInteger(), _params->GetG(), _params->GetG(),
        _element, _one_time_pub->GetInteger(), _author_pub->GetInteger(),
        t1, t2, t3);
    _challenge_1 = (_challenge_1 - f) % _params->GetQ();

    // chal_2 = f
    _challenge_2 = f;

    // resp_1 = v1 - (chal_1 * a)
    _response_1 = (v1 - (_challenge_1.MultiplyMod(_one_time_priv->GetInteger(), 
            _params->GetQ()))) % _params->GetQ();

    // resp_2 = v2
    _response_2 = v2;
  }

  bool ClientCiphertext::VerifyProof() const
  {
    // g1 = Product of server PKs, A = g1^a = client ciphertext elm,  a = client SK
    // g2 = DH key generator,      B = g2^b = client PK,              b = client SK
    // g3 = DH key generator,      C = g3^c = author PK,              c = author SK

    if(!(_params->IsElement(_one_time_pub->GetInteger()) &&
          _params->IsElement(_element))) return false;

    Integer t1, t2, t3;

    // t1 = A^chal1 * g1^resp1
    t1 = _params->GetP().PowCascade(_element, _challenge_1, 
        _server_pks->GetInteger(), _response_1);

    // t2 = B^chal1 * g2^resp1
    t2 = _params->GetP().PowCascade(_one_time_pub->GetInteger(), _challenge_1,
        _params->GetG(), _response_1);

    // t3 = C^chal2 * g3^resp2
    t3 = _params->GetP().PowCascade(_author_pub->GetInteger(), _challenge_2, 
        _params->GetG(), _response_2);

    Integer hash = Commit(_server_pks->GetInteger(), _params->GetG(), _params->GetG(),
        _element, _one_time_pub->GetInteger(), _author_pub->GetInteger(),
        t1, t2, t3);

    Integer sum = (_challenge_1 + _challenge_2) % _params->GetQ();
    return (sum == hash);
  }

  Integer ClientCiphertext::Commit(const Integer &g1, const Integer &g2, const Integer &g3,
      const Integer &y1, const Integer &y2, const Integer &y3,
      const Integer &t1, const Integer &t2, const Integer &t3) const
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    hash->Update(_params->GetP().GetByteArray());
    hash->Update(_params->GetQ().GetByteArray());
    hash->Update(_params->GetG().GetByteArray());

    hash->Update(g1.GetByteArray());
    hash->Update(g2.GetByteArray());
    hash->Update(g3.GetByteArray());

    hash->Update(y1.GetByteArray());
    hash->Update(y2.GetByteArray());
    hash->Update(y3.GetByteArray());

    hash->Update(t1.GetByteArray());
    hash->Update(t2.GetByteArray());
    hash->Update(t3.GetByteArray());

    return Integer(hash->ComputeHash()) % _params->GetQ();
  }

  QByteArray ClientCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_one_time_pub->GetByteArray());
    list.append(_element.GetByteArray());
    list.append(_challenge_1.GetByteArray());
    list.append(_challenge_2.GetByteArray());
    list.append(_response_1.GetByteArray());
    list.append(_response_2.GetByteArray());

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
  
  bool ClientCiphertext::VerifyProofs(const QList<QSharedPointer<const ClientCiphertext> > &c)
  {
    CryptoFactory::ThreadingType t = CryptoFactory::GetInstance().GetThreadingType();

    if(t == CryptoFactory::SingleThreaded) {
      for(int idx=0; idx<c.count(); idx++) {
        if(!c[idx]->VerifyProof()) return false;
      }
    } else if(t == CryptoFactory::MultiThreaded) {
      QList<bool> results = QtConcurrent::blockingMapped(c, &VerifyOnce);
      for(int idx=0; idx<c.count(); idx++) {
        if(!results[idx]) return false;
      }
    } else {
      qFatal("Unknown threading type");
    }

    return true;
  }

  bool ClientCiphertext::VerifyOnce(QSharedPointer<const ClientCiphertext> c) 
  {
    return c->VerifyProof();
  }
}
}
}
