#ifndef DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD

#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop server ciphertext
   */
  class ServerCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext
       * @param Group parameters
       * @param Client public keys
       */
      ServerCiphertext(const Parameters params, const PublicKeySet client_pks);

      /**
       * Constructor: Initialize a ciphertext from serialized version
       * @param Group parameters
       * @param Client public keys
       * @param serialized byte array
       */
      ServerCiphertext(const Parameters params, const PublicKeySet client_pks,
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~ServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param Server private key used to generate proof
       */
      void SetProof(const PrivateKey &priv);

      /**
       * Check ciphertext proof
       * @param public key of server
       * @param returns true if proof is okay
       */
      bool VerifyProof(const PublicKey &pub) const;

      /**
       * Get serialized version
       */
      QByteArray GetByteArray() const;

      inline Integer GetElement() const { return _element; }
      inline Integer GetChallenge() const { return _challenge; }
      inline Integer GetResponse() const { return _response; }

    private:

      Integer Commit(const Integer &g1, const Integer &g2, 
          const Integer &y1, const Integer &y2,
          const Integer &t1, const Integer &t2) const;

      Parameters _params;
      PublicKeySet _client_pks;

      Integer _element;
      Integer _challenge;
      Integer _response;
  };
}
}
}

#endif
