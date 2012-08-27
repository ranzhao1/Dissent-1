
#include <QtCore>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "PairingClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  PairingClientCiphertext::PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub) :
    ClientCiphertext(params, server_pks, author_pub, params->GetNElements())
  {
  }

  PairingClientCiphertext::PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      const QByteArray &serialized) :
    ClientCiphertext(params, server_pks, author_pub, params->GetNElements())
  {
    QList<QByteArray> list;
    QDataStream stream(serialized);
    stream >> list;

    // 2 challenges, 1 response, k elements
    if(list.count() != (3 + _n_elms)) {
      qWarning() << "Failed to unserialize";
      return; 
    }

    int list_idx = 0;
    _challenge_1 = Integer(list[list_idx++]);
    _challenge_2 = Integer(list[list_idx++]); 
    _response = Integer(list[list_idx++]); 

    for(int j=0; j<_n_elms; j++) { 
      _elements.append(_params->GetMessageGroup()->ElementFromByteArray(list[list_idx++]));
    }
  }

  void PairingClientCiphertext::SetAuthorProof(const QSharedPointer<const PrivateKey> author_priv, 
      const Plaintext &m)
  {
    QList<Element> ms = m.GetElements();
    for(int i=0; i<_n_elms; i++) {
      _elements[i] = _params->GetMessageGroup()->Multiply(_elements[i], ms[i]);
    }

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();
    
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
    Integer w = _params->GetKeyGroup()->RandomExponent();

    QList<Element> ts;
    QList<Integer> vs;

    Integer v_auth = _params->GetKeyGroup()->RandomExponent();
    ts.append(_params->GetKeyGroup()->Exponentiate(gs[0], v_auth));

    for(int i=0; i<(2*_n_elms); i++) { 
      Integer v = _params->GetMessageGroup()->RandomExponent();
      vs.append(v);

      ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[i+1], w, gs[i+1], v)); i++;
      ts.append(_params->GetMessageGroup()->CascadeExponentiate(ys[i+1], w, gs[i+1], v));
    }

    // h = H(gs, ys, ts)
    // chal_1 = h - w (mod q)
    _challenge_1 = (Commit(_params, gs, ys, ts) - w) % q;
    // chal_2 = w
    _challenge_2 = w;

    // r_auth = v_auth - (c1 * x_auth)
    _responses.append((v_auth - (_challenge_1 * author_priv->GetInteger())) % q);
    for(int i=0; i<_n_elms; i++) { 
      // r(i) = v(i) 
      _responses.append(vs[i]);
    }
  }

  void PairingClientCiphertext::SetProof()
  {
    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

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
    Integer w = _params->GetKeyGroup()->RandomExponent();

    QList<Element> ts;
    QList<Integer> vs;

    Integer v_auth = _params->GetKeyGroup()->RandomExponent();
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[0], w, gs[0], v_auth));

    for(int i=0; i<_n_elms; i++) { 
      vs.append(_params->GetKeyGroup()->RandomExponent());
    }

    int v_idx = 0;
    for(int i=1; i<(1+(2*_n_elms)); i++) {
      ts.append(_params->GetKeyGroup()->Exponentiate(gs[i], vs[v_idx])); i++;
      ts.append(_params->GetMessageGroup()->Exponentiate(gs[i], vs[v_idx]));

      v_idx++;
    }

    Q_ASSERT(v_idx == (_n_elms));
    Q_ASSERT(ts.count() == (1+(2*_n_elms)));
    Q_ASSERT(vs.count() == _n_elms);

    // h = H(gs, ys, ts)
    // chal_1 = w
    _challenge_1 = w;
    // chal_2 = h - w (mod q)
    _challenge_2 = (Commit(_params, gs, ys, ts) - w) % q;

    // r_auth = v_auth
    _responses.append(v_auth);
    for(int i=0; i<_n_elms; i++) { 
      // r(i) = v(i) - (c2 * secret_key_i)
      _responses.append((vs[i] - (_challenge_2 * _one_time_privs[i]->GetInteger())) % q);
    }
  }

  bool PairingClientCiphertext::VerifyProof() const
  {
    if(_elements.count() != _n_elms) {
      qWarning() << "Got proof with incorrect number of elements (" << _elements.count() << ")";
      return false;
    }

    if(_responses.count() != (1+_n_elms)) {
      qWarning() << "Got proof with incorrect number of responses (" << _responses.count() << ")";
      return false;
    }

    for(int i=0; i<_n_elms; i++) { 
      if(!(_params->GetKeyGroup()->IsElement(_one_time_pubs[i]->GetElement()) &&
            _params->GetMessageGroup()->IsElement(_elements[i]))) {
        qWarning() << "Got proof with invalid group element";
        return false;
      }
    }

    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

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
    ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[0], _challenge_1,
          gs[0], _responses[0]));

    int response_idx = 1;
    for(int i=1; i<(1+(2*_n_elms)); i++) {
      ts.append(_params->GetKeyGroup()->CascadeExponentiate(ys[i], _challenge_2,
          gs[i], _responses[response_idx]));
      i++;
      ts.append(_params->GetMessageGroup()->CascadeExponentiate(ys[i], _challenge_2,
          gs[i], _responses[response_idx]));

      response_idx++;
    }

    Integer hash = Commit(_params, gs, ys, ts);
    Integer sum = (_challenge_1 + _challenge_2) % q;

    return (sum == hash);
  }

  QByteArray PairingClientCiphertext::GetByteArray() const 
  {
    QList<QByteArray> list;

    list.append(_challenge_1.GetByteArray());
    list.append(_challenge_2.GetByteArray());
    list.append(_response.GetByteArray());

    for(int i=0; i<_n_elms; i++) { 
      list.append(_params->GetMessageGroup()->ElementToByteArray(_elements[i]));
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << list;
    return out;
  }
  
  void PairingClientCiphertext::InitializeLists(QList<Element> &gs, QList<Element> &ys) const
  { 
    XXX
    const Element g_key = _params->GetKeyGroup()->GetGenerator();
    const Integer q = _params->GetGroupOrder();

    // g_auth = DH base
    // g(i) = DH base
    // g'(i) = product of server PKs
    // ...
    gs.append(g_key);
    for(int i=0; i<_n_elms; i++) { 
      gs.append(g_key);
      gs.append(_server_pks->GetElement());
    }

    // y_auth = author PK
    // y(i) = one-time PK i
    // y'(i) = client ciphertext element i
    // ...
    ys.append(_author_pub->GetElement());
    for(int i=0; i<_n_elms; i++) { 
      ys.append(_one_time_pubs[i]->GetElement());
      ys.append(_elements[i]);
    }
  }

  Integer PairingClientCiphertext::Commit(const QSharedPointer<const Parameters> &params,
      const QList<Element> &gs, 
      const QList<Element> &ys, 
      const QList<Element> &ts) const
  {
    XXX
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();

    hash->Restart();
    hash->Update(params->GetKeyGroup()->GetByteArray());
    hash->Update(params->GetMessageGroup()->GetByteArray());

    Q_ASSERT(gs.count() == ys.count());
    Q_ASSERT(gs.count() == ts.count());

    for(int i=0; i<gs.count(); i++) {
      QSharedPointer<const Crypto::AbstractGroup::AbstractGroup> group = 
        ((!i) ? params->GetKeyGroup() : params->GetMessageGroup());

      hash->Update(group->ElementToByteArray(gs[i]));
      hash->Update(group->ElementToByteArray(ys[i]));
      hash->Update(group->ElementToByteArray(ts[i]));
    }

    return Integer(hash->ComputeHash()) % params->GetGroupOrder();
  }

}
}
}
