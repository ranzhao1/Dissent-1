#ifndef DISSENT_CRYPTO_BLOGDROP_HASHING_GEN_CLIENT_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_HASHING_GEN_CLIENT_CIPHERTEXT_H_GUARD

#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop client ciphertext using
   * Bryan's faster changing-generator construction. 
   * The generator gt changes with time t, and the
   * discrete log relationship of the generators is
   * unknown to everyone (i.e., the generators are 
   * picked using a public hash function).
   *   
   * Every client i and server j agree on a secret
   * s_ij, and they commit to this secret as
   *   commit[i,j] = g^{s_ij}
   *
   * The user private key is then:
   *   sk[i] = s_{i1} + ... + s{iM}
   *
   * The user public key is then:
   *   pk[i] = commit[i,1] * ... * commit[i,M]
   *         = g^{s_i1 + ... + s_iM}
   *
   * The then proves that:
   *   (Ci == gt^a AND Si = g^a) OR user_is_author
   *  
   * The full proof looks like:
   *   PoK{ a, y: 
   *      ( C1 = (g1)^a AND
   *        ... AND
   *        Ck = (gk)^a AND pk[i] = g^a
   *      OR
   *        Y = g^y
   *   }
   * where C1, ..., Ck are the k ciphertext elements, 
   * g1, ..., gk are generators, pk[i] is as above,
   * and Y is the author public key.
   */
  class HashingGenClientCiphertext : public ClientCiphertext {

    public:

      /**
       * Constructor: Initialize a ciphertext with a fresh
       * one-time public key
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       */
      explicit HashingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub);

      /**
       * Constructor: Initialize a ciphertext from a serialized bytearray
       * @param params Group parameters
       * @param server_pks Server public keys
       * @param author_pub author public key
       * @param the byte array
       */
      explicit HashingGenClientCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> server_pks,
          const QSharedPointer<const PublicKey> author_pub, 
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~HashingGenClientCiphertext() {}

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

      Element GetPairedBase(QHash<int, Element> &cache,
          const QSharedPointer<const PublicKeySet> server_pks, 
          int phase, int element_idx) const;
      void InitializeLists(QHash<int, Element> &cache,
          int phase, QSharedPointer<const PublicKey> client_pub,
          QList<Element> &gs, QList<Element> &ys) const;
      void InitCiphertext(int phase, const QSharedPointer<const PrivateKey> priv);

      QHash<int, Element> _cache;
      Integer _challenge_1;
      Integer _challenge_2;
      Integer _response_1;
      Integer _response_2;
  };
}
}
}

#endif
