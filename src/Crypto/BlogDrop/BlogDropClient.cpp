
#include "BlogDropClient.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropClient::BlogDropClient(const Parameters params, const PublicKeySet server_pks,
      const PublicKey author_pub) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub)
  {
  }

  ClientCiphertext BlogDropClient::GenerateCoverCiphertext() const 
  {
    ClientCiphertext c(_params, _server_pks, _author_pub);
    c.SetProof();
    return c;
  }

}
}
}
