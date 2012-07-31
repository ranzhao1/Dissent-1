#ifndef DISSENT_CRYPTO_BLOGDROP_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_CLIENT_CIPHERTEXT_H_GUARD

#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "Plaintext.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext
   */
  class ClientCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit ClientCiphertext(const Parameters params, const PublicKeySet server_pks,
          const PublicKey author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit ClientCiphertext(const Parameters params, const PublicKeySet server_pks,
          const PublicKey author_pub, const QByteArray &serialized);

      /**
       * Constructor: Initialize a ciphertext with an existing
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param one_time_pub the client's one-time public key
       */
      explicit ClientCiphertext(const Parameters params, const PublicKeySet server_pks,
          const PublicKey author_pub, const PublicKey one_time_pub);

      /**
       * Destructor
       */
      virtual ~ClientCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param author_priv author private key used to generate proof
       * @param m author's plaintext message
       */
      void SetAuthorProof(const PrivateKey &author_priv, const Plaintext &m);

      /**
       * Initialize elements proving correctness of ciphertext
       * @param client private key used to generate proof
       */
      void SetProof();

      /**
       * Check ciphertext proof
       * @returns true if proof is okay
       */
      bool VerifyProof() const;

      /**
       * Get a byte array for this ciphertext
       */
      QByteArray GetByteArray() const;

      inline PublicKey GetOneTimeKey() const { return _one_time_pub; }
      inline Integer GetElement() const { return _element; }
      inline Integer GetChallenge1() const { return _challenge_1; }
      inline Integer GetChallenge2() const { return _challenge_2; }
      inline Integer GetResponse1() const { return _response_1; }
      inline Integer GetResponse2() const { return _response_2; }

    private:

      Integer Commit(const Integer &g1, const Integer &g2, const Integer &g3,
          const Integer &y1, const Integer &y2, const Integer &y3,
          const Integer &t1, const Integer &t2, const Integer &t3) const;

      Parameters _params;
      PublicKeySet _server_pks;
      PublicKey _author_pub;

      PrivateKey _one_time_priv;
      PublicKey _one_time_pub;

      Integer _element;
      Integer _challenge_1, _challenge_2;
      Integer _response_1, _response_2;
  };
}
}
}

#endif
