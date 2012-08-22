
#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> params,
      int n_elms) :
    _params(params),
    _n_elms(n_elms)
  {}

}
}
}
