
#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> client_pks) :
    _params(params),
    _client_pks(client_pks)
  {
  }

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> client_pks,
      const QByteArray &serialized) :
    _params(params),
    _client_pks(client_pks)
  {
    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    if(list.count() != 3) {
      qWarning() << "Failed to unserialize";
      return; 
    }

    _element = _params->GetGroup()->ElementFromByteArray(list[0]);
    _challenge = Integer(list[1]);
    _response = Integer(list[2]);

  }

  void ServerCiphertext::SetProof(const QSharedPointer<const PrivateKey> priv)
  {
    // element = (prod of client_pks)^-server_sk mod p
    _element = _params->GetGroup()->Exponentiate(
          _client_pks->GetElement(), priv->GetInteger()); 
    _element = _params->GetGroup()->Inverse(_element);

    Integer v; 
    Element t1, t2;

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();
      
    // v in [0,q) 
    v = _params->GetGroup()->RandomExponent();

    // g1 = DH generator
    // g2 = product of client PKs

    // t1 = g1^v
    t1 = _params->GetGroup()->Exponentiate(g, v);

    // t2 = g2^-v
    t2 = _params->GetGroup()->Exponentiate(_client_pks->GetElement(), v);
    t2 = _params->GetGroup()->Inverse(t2);

    // y1 = server PK
    // y2 = server ciphertext
   
    // c = HASH(g1, g2, y1, y2, t1, t2) mod q
    _challenge = Commit(g, _client_pks->GetElement(),
        PublicKey(priv).GetElement(), _element,
        t1, t2);

    // r = v - cx == v - (chal)server_sk
    _response = (v - (_challenge.MultiplyMod(priv->GetInteger(), q))) % q;

  }

  bool ServerCiphertext::VerifyProof(const QSharedPointer<const PublicKey> pub) const
  {
    // g1 = DH generator 
    // g2 = product of all client pub keys
    // y1 = server PK
    // y2 = server ciphertext
    // t'1 = g1^r  * y1^c
    // t'2 = g2^-r  * y2^c

    if(!(_params->GetGroup()->IsElement(pub->GetElement()) &&
      _params->GetGroup()->IsElement(_client_pks->GetElement()) &&
      _params->GetGroup()->IsElement(_element))) {
      qDebug() << "Proof contains illegal group elements";
      return false;
    }

    Element t1, t2;

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    // t1 = g1^r * y1^c
    t1 = _params->GetGroup()->CascadeExponentiate(g, _response,
        pub->GetElement(), _challenge);

    // t2 = g2^-r * y2^c
    t2 = _params->GetGroup()->Exponentiate(_client_pks->GetElement(), _response);
    t2 = _params->GetGroup()->Inverse(t2);
    Element t2_tmp = _params->GetGroup()->Exponentiate(_element, _challenge);
    t2 = _params->GetGroup()->Multiply(t2, t2_tmp);
    
    Integer tmp = Commit(g, _client_pks->GetElement(),
        pub->GetElement(), _element,
        t1, t2);

    return (tmp == _challenge);
  }

  Integer ServerCiphertext::Commit(const Element &g1, const Element &g2, 
      const Element &y1, const Element &y2,
      const Element &t1, const Element &t2) const
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();

    hash->Restart();

    hash->Update(_params->GetGroup()->GetByteArray());

    hash->Update(g1.GetByteArray());
    hash->Update(g2.GetByteArray());

    hash->Update(y1.GetByteArray());
    hash->Update(y2.GetByteArray());

    hash->Update(t1.GetByteArray());
    hash->Update(t2.GetByteArray());

    return Integer(hash->ComputeHash()) % _params->GetGroup()->GetOrder();
  }

  QByteArray ServerCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_element.GetByteArray());
    list.append(_challenge.GetByteArray());
    list.append(_response.GetByteArray());

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
}
}
}
