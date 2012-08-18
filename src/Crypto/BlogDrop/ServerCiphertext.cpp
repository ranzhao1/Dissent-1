
#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const PublicKeySet> > &client_pks) :
    _params(params),
    _client_pks(client_pks)
  {
    if(_client_pks.count() != (_params->GetNElements())) {
      qFatal("Invalid pk list size");
    }
  }

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const PublicKeySet> > &client_pks,
      const QByteArray &serialized) :
    _params(params),
    _client_pks(client_pks)
  {
    if(_client_pks.count() != (_params->GetNElements())) {
      qFatal("Invalid pk list size");
    }

    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    // challenge, response, and k elements
    if(list.count() != (2 + _params->GetNElements())) {
      qWarning() << "Failed to unserialize";
      return; 
    }

    _challenge = Integer(list[0]);
    _response = Integer(list[1]);
    for(int i=0; i<_params->GetNElements(); i++) {
      _elements.append(_params->GetGroup()->ElementFromByteArray(list[2+i]));
    }
  }

  void ServerCiphertext::SetProof(const QSharedPointer<const PrivateKey> priv)
  {
    const int nelms = _params->GetNElements();

    for(int i=0; i<nelms; i++) {
      // element[i] = (prod of client_pks[i])^-server_sk mod p
      Element e = _params->GetGroup()->Exponentiate(
            _client_pks[i]->GetElement(), priv->GetInteger()); 
      e = _params->GetGroup()->Inverse(e);
      _elements.append(e);
    }

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();
      
    // v in [0,q) 
    Integer v = _params->GetGroup()->RandomExponent();

    QList<Element> gs;

    // g0 = DH generator
    gs.append(g);
    for(int i=0; i<nelms; i++) {
      // g(i) = product of client PKs i
      gs.append(_client_pks[i]->GetElement());
    }


    QList<Element> ts;

    // t0 = g0^v
    ts.append(_params->GetGroup()->Exponentiate(g, v));

    for(int i=0; i<nelms; i++) {
      // t(i) = g(i)^-v
      Element ti = _params->GetGroup()->Exponentiate(_client_pks[i]->GetElement(), v);
      ti = _params->GetGroup()->Inverse(ti);
      ts.append(ti);
    }

    QList<Element> ys;
    // y0 = server PK
    ys.append(PublicKey(priv).GetElement());
    for(int i=0; i<nelms; i++) {
      // y(i) = server ciphertext i
      ys.append(_elements[i]);
    }
   
    // c = HASH(g1, g2, ..., y1, y2, ..., t1, t2, ...) mod q
    _challenge = Commit(gs, ys, ts);

    // r = v - cx == v - (chal)server_sk
    _response = (v - (_challenge.MultiplyMod(priv->GetInteger(), q))) % q;
  }

  bool ServerCiphertext::VerifyProof(const QSharedPointer<const PublicKey> pub) const
  {
    // g0 = DH generator 
    // g(i) = product of all client pub keys i
    // y0 = server PK
    // y(i) = server ciphertext i
    // t'(0) = g0^r  * y0^c
    // t'(i) = g(i)^-r  * y(i)^c

    if(!(_params->GetGroup()->IsElement(pub->GetElement()))) { 
      qDebug() << "Proof contains illegal group elements";
      return false;
    }

    const int nelms = _params->GetNElements();

    for(int i=0; i<nelms; i++) {
      if(!_params->GetGroup()->IsElement(_client_pks[i]->GetElement()) &&
      _params->GetGroup()->IsElement(_elements[i])) {
        qDebug() << "Proof contains illegal group elements";
        return false;
      }
    }

    QList<Element> ts;

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    // t0 = g0^r * y0^c
    ts.append(_params->GetGroup()->CascadeExponentiate(g, _response,
        pub->GetElement(), _challenge));

    for(int i=0; i<nelms; i++) {
      // t(i) = g(i)^-r * y(i)^c
      Element ti = _params->GetGroup()->Exponentiate(_client_pks[i]->GetElement(), _response);
      ti = _params->GetGroup()->Inverse(ti);
      Element ti_tmp = _params->GetGroup()->Exponentiate(_elements[i], _challenge);
      ti = _params->GetGroup()->Multiply(ti, ti_tmp);
      ts.append(ti); 
    }

    QList<Element> gs;
    // g0 = DH generator
    gs.append(g);
    for(int i=0; i<nelms; i++) {
      // g(i) = product of client PKs i
      gs.append(_client_pks[i]->GetElement());
    }

    QList<Element> ys;
    // y0 = server PK
    ys.append(pub->GetElement());
    for(int i=0; i<nelms; i++) {
      // y(i) = server ciphertext i
      ys.append(_elements[i]);
    }
    
    Integer tmp = Commit(gs, ys, ts);
    return (tmp == _challenge);
  }

  Integer ServerCiphertext::Commit(const QList<Element> &gs,
          const QList<Element> &ys, const QList<Element> &ts) const
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();

    hash->Restart();
    hash->Update(_params->GetGroup()->GetByteArray());

    Q_ASSERT(gs.count() == (1+_params->GetNElements()));
    Q_ASSERT(ys.count() == (1+_params->GetNElements()));
    Q_ASSERT(ts.count() == (1+_params->GetNElements()));

    for(int i=0; i<_params->GetNElements(); i++) {
      hash->Update(_params->GetGroup()->ElementToByteArray(gs[i]));
      hash->Update(_params->GetGroup()->ElementToByteArray(ys[i]));
      hash->Update(_params->GetGroup()->ElementToByteArray(ts[i]));
    }

    return Integer(hash->ComputeHash()) % _params->GetGroup()->GetOrder();
  }

  QByteArray ServerCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_challenge.GetByteArray());
    list.append(_response.GetByteArray());
    for(int i=0; i<_params->GetNElements(); i++) {
      list.append(_params->GetGroup()->ElementToByteArray(_elements[i]));
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
}
}
}
