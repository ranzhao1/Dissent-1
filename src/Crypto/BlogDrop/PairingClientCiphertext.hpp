#ifndef DISSENT_CRYPTO_BLOGDROP_PAIRING_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PAIRING_CLIENT_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/PairingG1Group.hpp"
#include "Crypto/AbstractGroup/PairingGTGroup.hpp"

#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext using
   * pairing-based construction. Every ciphertext 
   * element is an element of the pairing target group GT
   *   
   * The proof for a ciphertext of length k has the form:
   *   PoK{ a, y: 
   *      ( C1 = e(prod_server_pks, t1)^a AND
   *        ... AND
   *        Ck = e(prod_server_pks, tk)^a AND A = g^a )
   *      OR
   *        Y = g^y
   *   }
   * where C1, ..., Ck are the k ciphertext elements, 
   * prod_server_pks is the product of server public keys,
   * A is the client's public key, and Y is 
   * the author public key.
   */
  class PairingClientCiphertext : public ClientCiphertext {

    public:

      typedef Crypto::AbstractGroup::PairingG1Group PairingG1Group;
      typedef Crypto::AbstractGroup::PairingGTGroup PairingGTGroup;

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit PairingClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~PairingClientCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase the message transmission phase/round index
       * @param client_priv client private key used to generate proof
       * @param author_priv author private key used to generate proof
       * @param m author's plaintext message
       */
      virtual void SetAuthorProof(int phase, 
          const QSharedPointer<const PrivateKey> client_priv,
          const QSharedPointer<const PrivateKey> author_priv, 
          const Plaintext &m);

      /**
       * Initialize elements proving correctness of ciphertext
       * @param phase the message transmission phase/round index
       * @param client_priv client private key used to generate proof
       */
      virtual void SetProof(int phase, const QSharedPointer<const PrivateKey> client_priv);

      /**
       * Check ciphertext proof
       * @returns true if proof is okay
       */
      virtual bool VerifyProof(int phase, const QSharedPointer<const PublicKey> client_pub) const;

      /**
       * Get a byte array for this ciphertext
       */
      virtual QByteArray GetByteArray() const;

      inline Integer GetChallenge1() const { return _challenge_1; }
      inline Integer GetChallenge2() const { return _challenge_2; }
      inline Integer GetResponse1() const { return _response_1; }
      inline Integer GetResponse2() const { return _response_2; }

    private:
      Integer Commit(const QSharedPointer<const Parameters> &params,
          const QList<Element> &gs, 
          const QList<Element> &ys, 
          const QList<Element> &ts) const;

      Element GetPairedBase(const QSharedPointer<const PublicKeySet> server_pks, 
          int phase, int element_idx) const;
      void InitializeLists(int phase, QSharedPointer<const PublicKey> client_pub,
          QList<Element> &gs, QList<Element> &ys) const;
      void InitCiphertext(int phase, const QSharedPointer<const PrivateKey> priv);

      Integer _challenge_1;
      Integer _challenge_2;
      Integer _response_1;
      Integer _response_2;

  };
}
}
}

#endif
