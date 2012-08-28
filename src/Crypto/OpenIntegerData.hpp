#ifndef DISSENT_CRYPTO_OPEN_INTEGER_DATA_H_GUARD
#define DISSENT_CRYPTO_OPEN_INTEGER_DATA_H_GUARD

#include <openssl/bn.h>
#include <string>

#include <QSharedData>
#include <QByteArray>
#include "IntegerData.hpp"
#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * "Big" OpenSSL IntegerData wrapper
   */

  static BN_CTX *SharedCtx = NULL;

  class OpenIntegerData : public IntegerData {

    public:
      /**
       * Construct using an int
       * @param value the int value
       */
      explicit OpenIntegerData(int value = 0)
      {
        Q_ASSERT(_bignum = BN_new());
        Q_ASSERT(BN_set_word(_bignum, value));
      }

      /**
       * Construct using an byte array
       * @param value the byte array
       */
      explicit OpenIntegerData(const QByteArray &byte_array) 
      {
        Q_ASSERT(_bignum = BN_new());
        Q_ASSERT(BN_bin2bn((const unsigned char*)byte_array.constData(), 
              byte_array.count(), _bignum));
      }

      /**
       * Construct using a base64 string
       * @param value the string
       */
      explicit OpenIntegerData(const QString &string)
      {
        QByteArray byte_array = FromBase64(string);
        Q_ASSERT(_bignum = BN_new());
        Q_ASSERT(BN_bin2bn((const unsigned char*)byte_array.constData(), 
              byte_array.count(), _bignum));
      }

      /**
       * Construct using allocated BIGNUM
       * @param bn the BIGNUM*
       */
      explicit OpenIntegerData(BIGNUM *bn) : _bignum(bn)
      {}

      /**
       * returns a random integer data
       * @param bit_count the amount of bits in the integer
       * @param prime if the integer should be prime 
       */
      static OpenIntegerData *GetRandomInteger(int bit_count, bool prime)
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        if(prime) {
          Q_ASSERT(BN_generate_prime(bn, bit_count, false, NULL, NULL, NULL, NULL));
        } else {
          Q_ASSERT(BN_rand(bn, bit_count, false, false));
        }
        return new OpenIntegerData(bn);
      }

      /**
       * returns a random integer data
       * @param min smallest number
       * @param max largest number
       * @param prime if the integer should be prime 
       */
      static OpenIntegerData *GetRandomInteger(const IntegerData *min,
          const IntegerData *max, bool prime)
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        BIGNUM *diff;
        Q_ASSERT(diff = BN_new());
        Q_ASSERT(BN_sub(diff, GetBignum(max), GetBignum(min)));

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        if(prime) {
          while(true) {
            Q_ASSERT(BN_rand_range(bn, diff));
            Q_ASSERT(BN_add(bn, bn, GetBignum(min)));
            if(BN_is_prime(bn, 80, NULL, SharedCtx, NULL)) break;
          }
        } else {
          Q_ASSERT(BN_rand_range(bn, diff));
          Q_ASSERT(BN_add(bn, bn, GetBignum(min)));
        }

        BN_clear_free(diff);

        return new OpenIntegerData(bn);
      }

      /**
       * Destructor
       */
      virtual ~OpenIntegerData() 
      {
        BN_clear_free(_bignum); 
      }

      /**
       * Add operator, produces a new Integer
       * @param other the Integer to add
       */
      virtual IntegerData *Add(const IntegerData *other) const
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        Q_ASSERT(BN_add(bn, _bignum, GetBignum(other)));
        return new OpenIntegerData(bn);
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param other the Integer to subtract (subtrahend)
       */
      virtual IntegerData *Subtract(const IntegerData *other) const
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        Q_ASSERT(BN_sub(bn, _bignum, GetBignum(other)));
        return new OpenIntegerData(bn);
      }

      /**
       * Subtraction operator, produces a new Integer
       * @param multiplicand the Integer to multiply this
       */
      virtual IntegerData *Multiply(const IntegerData *multiplicand) const
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        Q_ASSERT(BN_mul(bn, _bignum, GetBignum(multiplicand), SharedCtx));
        return new OpenIntegerData(bn);
      }

      /**
       * Division operator, produces a new Integer
       * @param divisor the Integer to divide into this
       */
      virtual IntegerData *Divide(const IntegerData *divisor) const
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        Q_ASSERT(BN_div(bn, NULL, _bignum, GetBignum(divisor), SharedCtx));
        return new OpenIntegerData(bn);
      }

      /**
       * Exponentiating operator
       * @param pow raise this to other
       */
      virtual IntegerData *Pow(const IntegerData *pow,
          const IntegerData *mod) const
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        Q_ASSERT(BN_mod_exp(bn, _bignum, GetBignum(pow), GetBignum(mod), SharedCtx));
        return new OpenIntegerData(bn);
      }

      /**
       * Cascade exponentiation modulo n
       * For integer n, compute ((x1^e1 * x2^e2) mod n)
       * This can be much faster than the naive way.
       * @param x1 first base
       * @param e1 first exponent
       * @param x2 second base
       * @param e2 second exponent
       */
      virtual IntegerData *PowCascade(const IntegerData *x1, const IntegerData *e1,
          const IntegerData *x2, const IntegerData *e2) const 
      {
        BIGNUM *bn;
        BIGNUM *bn2;
        Q_ASSERT(bn = BN_new());
        Q_ASSERT(bn2 = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        Q_ASSERT(BN_mod_exp(bn, GetBignum(x1), GetBignum(e1), _bignum, SharedCtx));
        Q_ASSERT(BN_mod_exp(bn2, GetBignum(x2), GetBignum(e2), _bignum, SharedCtx));
        BN_clear_free(bn2);
        Q_ASSERT(BN_mod_mul(bn, bn, bn2, _bignum, SharedCtx));
        return new OpenIntegerData(bn);
      }

      /**
       * Multiplication mod operator
       * @param other number to multiply
       * @param mod modulus
       */
      virtual IntegerData *MultiplyMod(const IntegerData *other,
          const IntegerData *mod) const
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        Q_ASSERT(BN_mod_mul(bn, _bignum, GetBignum(other), GetBignum(mod), SharedCtx));
        return new OpenIntegerData(bn);
      }

      /**
       * Modular multiplicative inverse
       * @param mod the modulus
       */
      virtual IntegerData *ModInverse(const IntegerData *mod) const
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        Q_ASSERT(BN_mod_inverse(bn, _bignum, GetBignum(mod), SharedCtx));
        return new OpenIntegerData(bn);
      }

      /**
       * Return a mod m
       * @param mod the modulus
       */
      virtual IntegerData *Modulo(const IntegerData *modulus) const 
      {
        BIGNUM *bn;
        Q_ASSERT(bn = BN_new());

        if(!SharedCtx) {
          Q_ASSERT(SharedCtx = BN_CTX_new());
        }

        Q_ASSERT(BN_mod(bn, _bignum, GetBignum(modulus), SharedCtx));
        return new OpenIntegerData(bn);
      }

      /**
       * Assignment operator
       * @param other the IntegerData to use for setting
       */
      virtual void Set(const IntegerData *other)
      {
        Q_ASSERT(BN_copy(_bignum, GetBignum(other)));
      }

      /**
       * Add operator, adds to current
       * @param other the IntegerData to add
       */
      virtual void operator+=(const IntegerData *other)
      {
        Q_ASSERT(BN_add(_bignum, _bignum, GetBignum(other)));
      }

      /**
       * Subtraction operator, subtracts from the current
       * @param other the IntegerData to subtract
       */
      virtual void operator-=(const IntegerData *other)
      {
        Q_ASSERT(BN_sub(_bignum, _bignum, GetBignum(other)));
      }

      /**
       * Equality operator
       * @param other the IntegerData to compare
       */
      virtual bool operator==(const IntegerData *other) const
      {
        return !BN_cmp(_bignum, GetBignum(other));
      }

      /**
       * Not equal operator
       * @param other the IntegerData to compare
       */
      virtual bool operator!=(const IntegerData *other) const
      {
        return (bool)BN_cmp(_bignum, GetBignum(other));
      }

      /**
       * Greater than
       * @param other the IntegerData to compare
       */
      virtual bool operator>(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) == 1);
      }

      /**
       * Greater than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator>=(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) > -1);
      }

      /**
       * Less than
       * @param other the IntegerData to compare
       */
      virtual bool operator<(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) == -1);
      }

      /**
       * Less than or equal
       * @param other the IntegerData to compare
       */
      virtual bool operator<=(const IntegerData *other) const
      {
        return (BN_cmp(_bignum, GetBignum(other)) < 1);
      }

      /**
       * Returns the integer's count in bits
       */
      virtual int GetBitCount() const
      {
        return 8*BN_num_bytes(_bignum);
      }

      /**
       * Returns the integer's count in bytes
       */
      virtual int GetByteCount() const
      {
        return BN_num_bytes(_bignum);
      }

      /**
       * Returns int32 rep
       */
      virtual int GetInt32() const
      {
        return (int)BN_get_word(_bignum);
      }

      /**
       * Returns the internal BIGNUM*
       */
      inline static BIGNUM* GetBignum(const IntegerData *data)
      {
        const OpenIntegerData *pcdata =
          dynamic_cast<const OpenIntegerData *>(data);
        if(pcdata) {
          return pcdata->_bignum;
        }

        return NULL;
      }

    protected:
      virtual void GenerateByteArray()
      {
        QByteArray byte_array(BN_num_bytes(_bignum), 0);
        if(BN_bn2bin(_bignum, (unsigned char*)byte_array.data())) { 
          SetByteArray(byte_array);
        } else {
          SetByteArray(QByteArray());
        }
      }

      virtual void GenerateCanonicalRep()
      {
        QByteArray byte_array(BN_num_bytes(_bignum), 0);
        Q_ASSERT(BN_bn2bin(_bignum, (unsigned char*)byte_array.data()));
        SetCanonicalRep(byte_array);
      }

    private:
      BIGNUM *_bignum;
  };
}
}

#endif
