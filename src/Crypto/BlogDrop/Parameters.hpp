#ifndef DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PARAMETERS_H_GUARD

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding group definition
   */
  class Parameters {

    public:

      /**
       * Constructor that generates new parameters
       */
      static Parameters Generate();

      /**
       * Constructor that uses fixed parameters
       */
      static Parameters Fixed();

      /**
       * Constructor with zeroed parameters
       */
      static Parameters Zero();

      /**
       * Destructor
       */
      virtual ~Parameters() {}

      /**
       * Return an integer in [0, q)
       */
      Integer RandomExponent() const;

      /**
       * Return an integer in g^{[0,q)}
       */
      Integer RandomElement() const;

      /**
       * Return true if i is a QR mod p
       * @param element to test
       */
      bool IsElement(const Integer &i) const;

      inline const Integer GetP() const { return _p; }
      inline const Integer GetQ() const { return _q; }
      inline const Integer GetG() const { return _g; }
      inline const Integer GetPSqrt() const { return _p_sqrt; }

      inline bool operator==(const Parameters &other) const {
        return (_p == other.GetP() &&
            _q == other.GetQ() &&
            _g == other.GetG() &&
            _p_sqrt == other.GetPSqrt());
      }

    private:
      /**
       * Private constructor
       * @param p must be a safe prime -- should have the
       *        form p = 2q+1 for a prime q
       * @param g must generate the large prime-order subgroup 
       *        group of Z*_p
       */
      Parameters(const Integer p, const Integer g);

      Parameters();

      Integer _p;
      /**
       * Equal to (p-1)/2. Useful for testing if an element
       * is a QR mod p, since:
       *
       *   (a is QR_p) iff (a^{(p-1)/2} == a^q == 1 mod p)
       */
      Integer _q;

      /**
       * Generator of group
       */
      Integer _g;

      /** 
       * Equal to (p+1)/4. Useful for taking square roots
       * modulo p, since:
       * 
       *   sqrt(a) = +/- a^{(p+1)/4}
       */
      Integer _p_sqrt; 

  };
}
}
}

#endif
