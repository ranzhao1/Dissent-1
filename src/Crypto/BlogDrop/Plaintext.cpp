
#include "Plaintext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  Plaintext::Plaintext(const QSharedPointer<const Parameters> params) :
    _params(params),
    _m(params->GetGroup()->GetIdentity())
  {}

  void Plaintext::Encode(const QByteArray &input)
  {
    _m = _params->GetGroup()->EncodeBytes(input);
  }

  bool Plaintext::Decode(QByteArray &ret) const 
  {
    return _params->GetGroup()->DecodeBytes(_m, ret);
  }

  void Plaintext::SetRandom()
  {
    _m = _params->GetGroup()->RandomElement();
  }

  void Plaintext::Reveal(const Element &c)
  {
    _m = _params->GetGroup()->Multiply(_m, c);
  }

}
}
}
