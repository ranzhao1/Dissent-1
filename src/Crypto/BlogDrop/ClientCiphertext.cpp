
#include <QtCore>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
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
    _nelms(_params->GetNElements())
  {
    for(int i=0; i<_nelms; i++) { 
      QSharedPointer<const PrivateKey> priv(new PrivateKey(_params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      _one_time_privs.append(priv);
      _one_time_pubs.append(pub);
      _elements.append(_params->GetGroup()->Exponentiate(_server_pks->GetElement(),
          _one_time_privs[i]->GetInteger())); 
    }
  }

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _nelms(_params->GetNElements())
  {
    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    // 2 challenges, k public keys, k elements, k+1 responses
    if(list.count() != (2 + _nelms + _nelms + (1+_nelms))) {
      qWarning() << "Failed to unserialize";
      return; 
    }

    int list_idx = 0;
    _challenge_1 = Integer(list[list_idx++]);
    _challenge_2 = Integer(list[list_idx++]); 

    for(int j=0; j<_nelms; j++) { 
      _elements.append(_params->GetGroup()->ElementFromByteArray(list[list_idx++]));
    }

    for(int j=0; j<_nelms; j++) { 
      _one_time_pubs.append(QSharedPointer<const PublicKey>(
            new PublicKey(params, list[list_idx++])));
    }

    _responses.append(Integer(list[list_idx++])); 

    for(int j=0; j<_nelms; j++) { 
      _responses.append(Integer(list[list_idx++]));
    }
  }

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      QList<QSharedPointer<const PublicKey> > one_time_pubs) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _one_time_pubs(one_time_pubs),
    _nelms(_params->GetNElements())
  {}

  void ClientCiphertext::SetAuthorProof(const QSharedPointer<const PrivateKey> author_priv, 
      const Plaintext &m)
  {
    QList<Element> ms = m.GetElements();
    for(int i=0; i<_nelms; i++) {
      _elements[i] = _params->GetGroup()->Multiply(_elements[i], ms[i]);
    }

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();
    
    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(gs, ys);

    // t_auth = * (g_auth)^{v_auth} 
    // t(i) = yi^w * gi^vi
    // t'(i) = y'i^w *  g'i^vi
    // ...
    Integer w = _params->GetGroup()->RandomExponent();

    QList<Element> ts;
    QList<Integer> vs;

    Integer v_auth = _params->GetGroup()->RandomExponent();
    ts.append(_params->GetGroup()->Exponentiate(gs[0], v_auth));

    for(int i=0; i<(2*_nelms); i++) { 
      Integer v = _params->GetGroup()->RandomExponent();
      vs.append(v);

      ts.append(_params->GetGroup()->CascadeExponentiate(ys[i+1], w, gs[i+1], v)); i++;
      ts.append(_params->GetGroup()->CascadeExponentiate(ys[i+1], w, gs[i+1], v));
    }

    // h = H(gs, ys, ts)
    // chal_1 = h - w (mod q)
    _challenge_1 = (BlogDropUtils::Commit(_params, gs, ys, ts) - w) % q;
    // chal_2 = w
    _challenge_2 = w;

    // r_auth = v_auth - (c1 * x_auth)
    _responses.append((v_auth - (_challenge_1 * author_priv->GetInteger())) % q);
    for(int i=0; i<_nelms; i++) { 
      // r(i) = v(i) 
      _responses.append(vs[i]);
    }
  }

  void ClientCiphertext::SetProof()
  {
    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(gs, ys);

    // t_auth = (y_auth)^w * (g_auth)^{v_auth} 
    // t(i) = gi^vi
    // t'(i) = g'(i)^v'(i)
    // ...
    Integer w = _params->GetGroup()->RandomExponent();

    QList<Element> ts;
    QList<Integer> vs;

    Integer v_auth = _params->GetGroup()->RandomExponent();
    ts.append(_params->GetGroup()->CascadeExponentiate(ys[0], w, gs[0], v_auth));

    for(int i=0; i<_nelms; i++) { 
      vs.append(_params->GetGroup()->RandomExponent());
    }

    int v_idx = 0;
    for(int i=1; i<(1+(2*_nelms)); i++) {
      ts.append(_params->GetGroup()->Exponentiate(gs[i], vs[v_idx])); i++;
      ts.append(_params->GetGroup()->Exponentiate(gs[i], vs[v_idx]));

      v_idx++;
    }

    Q_ASSERT(v_idx == (_nelms));
    Q_ASSERT(ts.count() == (1+(2*_nelms)));
    Q_ASSERT(vs.count() == _nelms);

    // h = H(gs, ys, ts)
    // chal_1 = w
    _challenge_1 = w;
    // chal_2 = h - w (mod q)
    _challenge_2 = (BlogDropUtils::Commit(_params, gs, ys, ts) - w) % q;

    // r_auth = v_auth
    _responses.append(v_auth);
    for(int i=0; i<_nelms; i++) { 
      // r(i) = v(i) - (c2 * secret_key_i)
      _responses.append((vs[i] - (_challenge_2 * _one_time_privs[i]->GetInteger())) % q);
    }
  }

  bool ClientCiphertext::VerifyProof() const
  {
    if(_elements.count() != _nelms) {
      qWarning() << "Got proof with incorrect number of elements (" << _elements.count() << ")";
      return false;
    }

    if(_responses.count() != (1+_nelms)) {
      qWarning() << "Got proof with incorrect number of responses (" << _responses.count() << ")";
      return false;
    }

    for(int i=0; i<_nelms; i++) { 
      if(!(_params->GetGroup()->IsElement(_one_time_pubs[i]->GetElement()) &&
            _params->GetGroup()->IsElement(_elements[i]))) {
        qWarning() << "Got proof with invalid group element";
        return false;
      }
    }

    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    QList<Element> gs;
    QList<Element> ys;

    InitializeLists(gs, ys);

    // t_auth = (y_auth)^c1 * (g_auth)^{r_auth}
    // t(i) = y1^c2 * g1^r1
    // t'(i) = y'1^c2 * g'1^r1
    // ...
    QList<Element> ts;
    ts.append(_params->GetGroup()->CascadeExponentiate(ys[0], _challenge_1,
          gs[0], _responses[0]));

    int response_idx = 1;
    for(int i=1; i<(1+(2*_nelms)); i++) {
      ts.append(_params->GetGroup()->CascadeExponentiate(ys[i], _challenge_2,
          gs[i], _responses[response_idx]));
      i++;
      ts.append(_params->GetGroup()->CascadeExponentiate(ys[i], _challenge_2,
          gs[i], _responses[response_idx]));

      response_idx++;
    }

    Integer hash = BlogDropUtils::Commit(_params, gs, ys, ts);
    Integer sum = (_challenge_1 + _challenge_2) % q;

    return (sum == hash);
  }

  QByteArray ClientCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_challenge_1.GetByteArray());
    list.append(_challenge_2.GetByteArray());

    for(int i=0; i<_nelms; i++) { 
      list.append(_params->GetGroup()->ElementToByteArray(_elements[i]));
    }

    for(int i=0; i<_nelms; i++) { 
      list.append(_one_time_pubs[i]->GetByteArray());
    }

    for(int i=0; i<_responses.count(); i++) { 
      list.append(_responses[i].GetByteArray());
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
  
  QSet<int> ClientCiphertext::VerifyProofs(const QList<QSharedPointer<const ClientCiphertext> > &c)
  {
    // XXX Only allowing single-threaded mode for now. Need to add
    // synchronization to ECGroup classes if for multi-threading to
    // work.
    // CryptoFactory::ThreadingType t = CryptoFactory::GetInstance().GetThreadingType();
    CryptoFactory::ThreadingType t = CryptoFactory::SingleThreaded;
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

  void ClientCiphertext::InitializeLists(QList<Element> &gs, QList<Element> &ys) const
  { 
    const Element g = _params->GetGroup()->GetGenerator();
    const Integer q = _params->GetGroup()->GetOrder();

    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    gs.append(g);
    for(int i=0; i<_nelms; i++) { 
      gs.append(g);
      gs.append(_server_pks->GetElement());
    }

    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    ys.append(_author_pub->GetElement());
    for(int i=0; i<_nelms; i++) { 
      ys.append(_one_time_pubs[i]->GetElement());
      ys.append(_elements[i]);
    }
  }

  bool ClientCiphertext::VerifyOnce(QSharedPointer<const ClientCiphertext> c) 
  {
    return c->VerifyProof();
  }

}
}
}
