
#include "OpenECElementData.hpp"
#include "OpenECGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  OpenECGroup::OpenECGroup(BIGNUM *p, BIGNUM *q, BIGNUM *a, 
      BIGNUM *b, BIGNUM *gx, BIGNUM *gy) :
      _p(p),
      _q(q),
      _a(a),
      _b(b),
      _gx(gx),
      _gy(gy),
      _zero(BN_new()),
      _one(BN_new()),
      _tmp0(BN_new()),
      _tmp1(BN_new()),
      _ctx(BN_CTX_new()),
      _group(EC_GROUP_new_curve_GFp(_p, _a, _b, _ctx)),
      _generator(EC_POINT_new(_group))
    {
      Q_ASSERT(_group);
      Q_ASSERT(!BN_zero(_zero));
      Q_ASSERT(!BN_one(_one));

      // affine coordinates are the "normal" (x,y) pairs
      Q_ASSERT(!EC_POINT_set_affine_coordinates_GFp(_group, 
            _generator, _gx, _gy, _xtx));

      // precompute multiplication helper data
      Q_ASSERT(!EC_GROUP_precompute_mult(_group, _ctx);

      // Cofactor of our curves are always 1
      Q_ASSERT(!EC_GROUP_set_generator(_group, _generator, _q, _one));
    };

  OpenECGroup::~OpenECGroup() 
  {
    EC_POINT_clear_free(_generator);
    EC_GROUP_clear_freee(_group);

    BN_CTX_free(_ctx);

    BN_clear_free(_p);
    BN_clear_free(_q);
    BN_clear_free(_a);
    BN_clear_free(_b);
    BN_clear_free(_gx);
    BN_clear_free(_gy);
    BN_free(_one);
    BN_free(_zero);

    BN_clear_free(_tmp0);
    BN_clear_free(_tmp1);
  }

  QSharedPointer<OpenECGroup> OpenECGroup::ProductionFixed() 
  {
    // RFC 5903 - 256-bit curve
    const char *str_p = "0xFFFFFFFF000000010000000000"
                    "00000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
    const char *str_q = "0xFFFFFFFF00000000FFFFFFFFFF"
                    "FFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

    const char *str_a = "-3";
    const char *str_b = "0x5AC635D8AA3A93E7B3EBBD5576"
                    "9886BC651D06B0CC53B0F63BCE3C3E27D2604B";

    const char *str_gx = "0x6B17D1F2E12C4247F8BCE6E56"
                     "3A440F277037D812DEB33A0F4A13945D898C296";
    const char *str_gy = "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE3"
                     "3576B315ECECBB6406837BF51F5";

    BIGNUM *p, *q, *a, *b, *gx, *gy;
    BN_hex2bn(&p, str_p);
    BN_hex2bn(&q, str_q);
    BN_hex2bn(&a, str_a);
    BN_hex2bn(&b, str_b);
    BN_hex2bn(&gx, str_gx);
    BN_hex2bn(&gy, str_gy);

    Q_ASSERT(p);
    Q_ASSERT(q);
    Q_ASSERT(a);
    Q_ASSERT(b);
    Q_ASSERT(gx);
    Q_ASSERT(gy);

    return QSharedPointer<OpenECGroup>(new OpenECGroup(p, q, a, b, gx, gy));
  }

  Element OpenECGroup::Multiply(const Element &a, const Element &b) const
  {
    EC_POINT *r = EC_POINT_new(_group);
    Q_ASSERT(r);

    // r = a + b
    Q_ASSERT(!EC_POINT_add(_group, r, GetPoint(a), GetPoint(b), _ctx));

    return Element(new OpenECElementData(r));
  }

  Element OpenECGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    EC_POINT *r = EC_POINT_new(_group);
    Q_ASSERT(r);

    EC_POINT *ps[1];
    BIGNUM *ms[1];

    GetInteger(_tmp0, exp);

    ps[0] = GetPoint(a);
    ms[0] = _tmp0;

    Q_ASSERT(!EC_POINTs_mul(_group, r, _zero, 1, ps, ms, _ctx));

    return Element(new OpenECElementData(r));
  }
  
  Element OpenECGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    EC_POINT *r = EC_POINT_new(_group);
    Q_ASSERT(r);

    EC_POINT *ps[2];
    BIGNUM *ms[2];

    GetInteger(_tmp0, e1);
    GetInteger(_tmp1, e2);

    ps[0] = GetPoint(a1);
    ps[1] = GetPoint(a2);
    ms[0] = _tmp0;
    ms[1] = _tmp2;

    Q_ASSERT(!EC_POINTs_mul(_group, r, _zero, 2, ps, ms, _ctx));

    return Element(new OpenECElementData(r));
  }

  Element OpenECGroup::Inverse(const Element &a) const
  {
    EC_POINT *r = EC_POINT_dup(GetPoint(a));
    Q_ASSERT(r);

    Q_ASSERT(!EC_POINT_invert(_group, r, _ctx));
    return Element(new OpenECElementData(r));
  }
  
  QByteArray OpenECGroup::ElementToByteArray(const Element &a) const
  {
    /*
    const unsigned int nbytes = _curve.EncodedPointSize(false);
    QByteArray out(nbytes, 0);
    _curve.EncodePoint((unsigned char*)(out.data()), GetPoint(a), false);
    */
    return out;
  }
  
  Element OpenECGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    /*
    CryptoPP::ECPPoint point;
    _curve.DecodePoint(point, 
        (const unsigned char*)(bytes.constData()), 
        bytes.count());
        */
    return Element(new OpenECElementData(point));
  }

  bool OpenECGroup::IsElement(const Element &a) const 
  {
    return _curve.VerifyPoint(GetPoint(a));
  }

  bool OpenECGroup::IsIdentity(const Element &a) const 
  {
    return (a == GetIdentity());
  }

  Integer OpenECGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }

  Element OpenECGroup::RandomElement() const
  {
    return Exponentiate(GetGenerator(), RandomExponent());
  }

  CryptoPP::ECPPoint OpenECGroup::GetPoint(const Element &e) const
  {
    return OpenECElementData::GetPoint(e.GetData());
  }

  Element OpenECGroup::EncodeBytes(const QByteArray &in) const
  {
    /*
    * See the article 
    *  "Encoding And Decoding  of  a Message in the 
    *  Implementation of Elliptic Curve Cryptography 
    *  using Koblitz’s Method" for details on how this works.
    * 
    * k == MessageSerializationParameter defines the percentage
    * chance that we won't be able to encode a given message
    * in a given elliptic curve point. The failure probability
    * is 2^(-k).
    *
    * We can store b = log_2(p/k) bytes in every 
    * elliptic curve point, where p is the security
    * parameter (prime size) of the elliptic curve.
    *
    * For p = 2^256, k = 256, b = 224 (minus 2 padding bytes)
    */

    if(in.count() > BytesPerElement()) {
      qFatal("Failed to serialize over-sized string");
    }

    // Holds the data to be encoded plus a leading and a trailing
    // 0xFF byte
    QByteArray data;
    data.append(0xff);
    data += in;
    data.append(0xff);

    // r is an encoding of the string in a big integer
    CryptoPP::Integer r(("0x"+data.toHex()).constData());

    qDebug() << "r" << Integer(new CppIntegerData(r)).GetByteArray().toHex();
    
    Q_ASSERT(r < _curve.FieldSize());

    Element point;
    CryptoPP::Integer x, y;
    for(int i=0; i<_k; i++) {
      // x = rk + i mod p
      x = ((r*_k)+i);

      Q_ASSERT(x < _curve.FieldSize());

      if(SolveForY(x, point)) {
        return point;
      } 
    }

    qFatal("Failed to find point");
    return Element(new OpenECElementData(CryptoPP::ECPPoint()));
  }
 
  bool OpenECGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    // output value = floor( x/k )
    CryptoPP::Integer x = GetPoint(a).x;
   
    // x = floor(x/k)
    CryptoPP::Integer remainder, quotient;
    CryptoPP::Integer::Divide(remainder, quotient, x, CryptoPP::Integer(_k));

    Integer intdata(new CppIntegerData(quotient));

    QByteArray data = intdata.GetByteArray(); 

    if(data.count() < 2) {
      qWarning() << "Data is too short";
      return false;
    }

    const unsigned char c = 0xff;
    const unsigned char d0 = data[0];
    const unsigned char dlast = data[data.count()-1];
    if((d0 != c) || (dlast != c)) {
      qWarning() << "Data has improper padding";
      return false;
    }

    out = data.mid(1, data.count()-2);
    return true;
  }

  bool OpenECGroup::IsProbablyValid() const
  {
    qDebug() << IsElement(GetGenerator());
    qDebug() << IsIdentity(Exponentiate(GetGenerator(), GetOrder()));

    return IsElement(GetGenerator()) && 
      IsIdentity(Exponentiate(GetGenerator(), GetOrder())) &&
      CryptoPP::IsPrime(_curve.FieldSize()) &&
      CryptoPP::IsPrime(ToCryptoInt(GetOrder()));
  }

  QByteArray OpenECGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << FromCryptoInt(_curve.FieldSize()).GetByteArray() 
      << FromCryptoInt(_curve.GetA()).GetByteArray()
      << FromCryptoInt(_curve.GetB()).GetByteArray();

    return out;
  }

  bool OpenECGroup::SolveForY(const CryptoPP::Integer &x, Element &point) const
  {
    // y^2 = x^3 + ax + b (mod p)

    CryptoPP::ModularArithmetic arith(_curve.FieldSize());

    // tmp = x
    CryptoPP::Integer tmp = x;

    // tmp = x^2
    tmp = arith.Square(tmp);

    // tmp = x^2 + a
    tmp = arith.Add(tmp, _curve.GetA());

    // tmp = x (x^2 + a) == (x^3 + ax)
    tmp = arith.Multiply(tmp, x);

    // tmp = x^3 + ax + b
    tmp = arith.Add(tmp, _curve.GetB());
   
    // does there exist y such that (y^2 = x^3 + ax + b) mod p ?

    // jacobi symbol is 1 if tmp is a non-trivial 
    // quadratic residue mod p
    bool solved = (CryptoPP::Jacobi(tmp, _curve.FieldSize()) == 1);

    if(solved) {
      const CryptoPP::Integer y = CryptoPP::ModularSquareRoot(tmp, _curve.FieldSize());

      point = Element(new OpenECElementData(CryptoPP::ECPPoint(x, y)));
      Q_ASSERT(IsElement(point));
    }

    return solved;
  }

  void GetInteger(BIGNUM *ret, const Integer &i) const 
  {
    Q_ASSERT(ret);
    Q_ASSERT(!BN_hex2bn(&ret, i.GetByteArray().constData().toHex()));  
    return r;
  }

  EC_POINT *GetPoint(const Element &e) const
  {
    return OpenECGroup::GetPoint(e.GetData());
  }

}
}
}
