
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
    _element(_params->GetGroup()->Exponentiate(_server_pks->GetElement(),
          _one_time_priv->GetInteger())) 
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

    _one_time_pub = QSharedPointer<const PublicKey>(new PublicKey(params, list[0]));
    _element = _params->GetGroup()->ElementFromByteArray(list[1]);
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
    _element = _params->GetGroup()->Multiply(_element, m.GetElement());

    // g1 = Product of server PKs, A = g1^a = client ciphertext elm,  a = client SK
    // g2 = DH key generator,      B = g2^b = client PK,              b = client SK
    // g3 = DH key generator,      C = g3^c = author PK,              c = author SK

    // f  = random element mod q
    // v1 = random element mod q
    // v2 = random element mod q

    Integer f, v1, v2;
    f = _params->GetGroup()->RandomExponent();
    v1 = _params->GetGroup()->RandomExponent();
    v2 = _params->GetGroup()->RandomExponent();

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    Element t1, t2, t3;

    // t1 = A^f * g1^v1
    t1 = _params->GetGroup()->CascadeExponentiate(_element, f, 
        _server_pks->GetElement(), v1);

    // t2 = B^f * g2^v1
    t2 = _params->GetGroup()->CascadeExponentiate(_one_time_pub->GetElement(), f, g, v1);

    // t3 = g3^v2
    t3 = _params->GetGroup()->Exponentiate(g, v2);

    // chal1 = f
    _challenge_1 = f;

    // chal2 = H(g1, g2, g3, y1, y2, y3, t1, t2, t3) - f
    Integer hash = Commit(_server_pks->GetElement(), g, g,
        _element, _one_time_pub->GetElement(), _author_pub->GetElement(),
        t1, t2, t3);

    _challenge_2 = (hash - f) % q;
   
    // resp1 = v1
    _response_1 = v1;

    // resp2 = v2 - (chal2 * c)
    _response_2 = (v2 - (_challenge_2.MultiplyMod(author_priv->GetInteger(), 
            q))) % q;
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
    f = _params->GetGroup()->RandomExponent();
    v1 = _params->GetGroup()->RandomExponent();
    v2 = _params->GetGroup()->RandomExponent();

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    Element t1, t2, t3;

    // t1 = g1^v1
    t1 = _params->GetGroup()->Exponentiate(_server_pks->GetElement(), v1);

    // t2 = g2^v1
    t2 = _params->GetGroup()->Exponentiate(g, v1);

    // t3 = C^f * g3^v2
    t3 = _params->GetGroup()->CascadeExponentiate(_author_pub->GetElement(), f, g, v2);

    // h = H(g1, g2, g3, y1, y2, y3, t1, t2, t3)
    // chal_1 = h - f1 (mod q)
    _challenge_1 = Commit(_server_pks->GetElement(), g, g,
        _element, _one_time_pub->GetElement(), _author_pub->GetElement(),
        t1, t2, t3);
    _challenge_1 = (_challenge_1 - f) % q;

    // chal_2 = f
    _challenge_2 = f;

    // resp_1 = v1 - (chal_1 * a)
    _response_1 = (v1 - (_challenge_1.MultiplyMod(_one_time_priv->GetInteger(), 
            q))) % q;

    // resp_2 = v2
    _response_2 = v2;
  }

  bool ClientCiphertext::VerifyProof() const
  {
    // g1 = Product of server PKs, A = g1^a = client ciphertext elm,  a = client SK
    // g2 = DH key generator,      B = g2^b = client PK,              b = client SK
    // g3 = DH key generator,      C = g3^c = author PK,              c = author SK

    if(!(_params->GetGroup()->IsElement(_one_time_pub->GetElement()) &&
          _params->GetGroup()->IsElement(_element))) return false;

    Element t1, t2, t3;
    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    // t1 = A^chal1 * g1^resp1
    t1 = _params->GetGroup()->CascadeExponentiate(_element, _challenge_1, 
        _server_pks->GetElement(), _response_1);

    // t2 = B^chal1 * g2^resp1
    t2 = _params->GetGroup()->CascadeExponentiate(_one_time_pub->GetElement(), _challenge_1,
        g, _response_1);

    // t3 = C^chal2 * g3^resp2
    t3 = _params->GetGroup()->CascadeExponentiate(_author_pub->GetElement(), _challenge_2, 
        g, _response_2);

    Integer hash = Commit(_server_pks->GetElement(), g, g, 
        _element, _one_time_pub->GetElement(), _author_pub->GetElement(),
        t1, t2, t3);

    Integer sum = (_challenge_1 + _challenge_2) % q;
    return (sum == hash);
  }

  Integer ClientCiphertext::Commit(const Element &g1, const Element &g2, const Element &g3,
      const Element &y1, const Element &y2, const Element &y3,
      const Element &t1, const Element &t2, const Element &t3) const
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    hash->Update(_params->GetGroup()->GetByteArray());

    hash->Update(_params->GetGroup()->ElementToByteArray(g1));
    hash->Update(_params->GetGroup()->ElementToByteArray(g2));
    hash->Update(_params->GetGroup()->ElementToByteArray(g3));

    hash->Update(_params->GetGroup()->ElementToByteArray(y1));
    hash->Update(_params->GetGroup()->ElementToByteArray(y2));
    hash->Update(_params->GetGroup()->ElementToByteArray(y3));

    hash->Update(_params->GetGroup()->ElementToByteArray(t1));
    hash->Update(_params->GetGroup()->ElementToByteArray(t2));
    hash->Update(_params->GetGroup()->ElementToByteArray(t3));

    return Integer(hash->ComputeHash()) % _params->GetGroup()->GetOrder();
  }

  QByteArray ClientCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_one_time_pub->GetByteArray());
    list.append(_params->GetGroup()->ElementToByteArray(_element));
    list.append(_challenge_1.GetByteArray());
    list.append(_challenge_2.GetByteArray());
    list.append(_response_1.GetByteArray());
    list.append(_response_2.GetByteArray());

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
  
  QSet<int> ClientCiphertext::VerifyProofs(const QList<QSharedPointer<const ClientCiphertext> > &c)
  {
    CryptoFactory::ThreadingType t = CryptoFactory::GetInstance().GetThreadingType();
    QSet<int> valid;

    if(t == CryptoFactory::SingleThreaded) {
      for(int idx=0; idx<c.count(); idx++) {
        if(c[idx]->VerifyProof()) valid.insert(idx);
      }
    } else if(t == CryptoFactory::MultiThreaded) {
      QList<bool> results = QtConcurrent::blockingMapped(c, &VerifyOnce);
      for(int idx=0; idx<c.count(); idx++) {
        if(results[idx]) valid.insert(idx);
      }
    } else {
      qFatal("Unknown threading type");
    }

    return valid;
  }

  bool ClientCiphertext::VerifyOnce(QSharedPointer<const ClientCiphertext> c) 
  {
    return c->VerifyProof();
  }
}
}
}
