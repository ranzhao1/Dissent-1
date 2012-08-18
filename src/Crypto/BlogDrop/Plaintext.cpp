
#include "Plaintext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Plaintext::Plaintext(const QSharedPointer<const Parameters> params) :
    _params(params)
  {
    for(int i=0; i<_params->GetNElements(); i++) {
      _ms.append(params->GetGroup()->GetIdentity());
    }
  }

  void Plaintext::Encode(const QByteArray &input)
  {
    QByteArray data = input;
    const int bytesper = _params->GetGroup()->BytesPerElement();

    for(int i=0; i<_params->GetNElements(); i++) {
      _ms[i] = _params->GetGroup()->EncodeBytes(data.left(bytesper));
      data = data.mid(bytesper);
    }
  }

  bool Plaintext::Decode(QByteArray &ret) const 
  {
    QByteArray out;
    for(int i=0; i<_params->GetNElements(); i++) {
      QByteArray tmp;
      if(!_params->GetGroup()->DecodeBytes(_ms[i], tmp)) return false;
      out += tmp;
    }

    ret = out;
    return true;
  }

  void Plaintext::SetRandom()
  {
    for(int i=0; i<_params->GetNElements(); i++) {
      _ms[i] = _params->GetGroup()->RandomElement();
    }
  }

  void Plaintext::Reveal(const QList<Element> &c)
  {
    Q_ASSERT(c.count() == _ms.count());

    for(int i=0; i<_params->GetNElements(); i++) {
      _ms[i] = _params->GetGroup()->Multiply(_ms[i], c[i]);
    }
  }

}
}
}
