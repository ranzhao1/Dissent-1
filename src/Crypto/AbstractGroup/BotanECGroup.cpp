
#include "BotanECElementData.hpp"
#include "BotanECGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  BotanECGroup::BotanECGroup(Integer p, Integer q, Integer a, Integer b, Integer gx, Integer gy) :
      _curve(ToBotanInt(p), ToBotanInt(a), ToBotanInt(b)),
      _q(q),
      _g(_curve, ToBotanInt(gx), ToBotanInt(gy)),
      _field_bytes(p.GetByteArray().count())
    {
      /*
      qDebug() << " p" << p.GetByteArray().toHex(); 
      qDebug() << " a" << a.GetByteArray().toHex(); 
      qDebug() << " b" << b.GetByteArray().toHex(); 
      qDebug() << "gx" << gx.GetByteArray().toHex(); 
      qDebug() << "gy" << gy.GetByteArray().toHex(); 
      */

      Q_ASSERT(ToBotanInt(p) == _curve.get_p());
    };


  QSharedPointer<BotanECGroup> BotanECGroup::ProductionFixed() 
  {
    // RFC 5903 - 256-bit curve
    const Integer p(QByteArray::fromHex("0xFFFFFFFF000000010000000000"
                                        "00000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));
    const Integer q(QByteArray::fromHex("0xFFFFFFFF00000000FFFFFFFFFF"
                                        "FFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));

    const Integer a(-3L);
    const Integer b(QByteArray::fromHex("0x5AC635D8AA3A93E7B3EBBD5576"
                                        "9886BC651D06B0CC53B0F63BCE3C3E27D2604B"));

    const Integer gx(QByteArray::fromHex("0x6B17D1F2E12C4247F8BCE6E56"
                                         "3A440F277037D812DEB33A0F4A13945D898C296"));
    const Integer gy(QByteArray::fromHex("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE3"
                                         "3576B315ECECBB6406837BF51F5"));

    return QSharedPointer<BotanECGroup>(new BotanECGroup(p, q, a, b, gx, gy));
  }

  Element BotanECGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new BotanECElementData(GetPoint(a) + GetPoint(b)));
  }

  Element BotanECGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new BotanECElementData(ToBotanInt(exp) * GetPoint(a)));
  }
  
  Element BotanECGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    return Element(new BotanECElementData(
          multi_exponentiate(GetPoint(a1), ToBotanInt(e1),
                            GetPoint(a2), ToBotanInt(e2))));
  }

  Element BotanECGroup::Inverse(const Element &a) const
  {
    return Element(new BotanECElementData(GetPoint(a).negate()));
  }
  
  QByteArray BotanECGroup::ElementToByteArray(const Element &a) const
  {
    Botan::SecureVector<byte> vec(Botan::EC2OSP(GetPoint(a), Botan::PointGFp::COMPRESSED));
    return QByteArray(reinterpret_cast<const char*>(&vec[0]), vec.size());
  }
  
  Element BotanECGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    Botan::SecureVector<byte> data(reinterpret_cast<const byte*>(bytes.constData()), bytes.count());
    return Element(new BotanECElementData(Botan::OS2ECP(data, _curve)));
  }

  bool BotanECGroup::IsElement(const Element &a) const 
  {
    return IsIdentity(a) || GetPoint(a).on_the_curve();
  }

  bool BotanECGroup::IsIdentity(const Element &a) const 
  {
    return GetPoint(a).is_zero();
  }

  Integer BotanECGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }

  Element BotanECGroup::RandomElement() const
  {
    return Exponentiate(GetGenerator(), RandomExponent());
  }

  Botan::PointGFp BotanECGroup::GetPoint(const Element &e) const
  {
    return BotanECElementData::GetPoint(e.GetData());
  }

  Element BotanECGroup::EncodeBytes(const QByteArray &in) const
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
    Botan::BigInt r;
    r.binary_decode(reinterpret_cast<const byte*>(data.constData()), data.count());

    //qDebug() << "r" << Integer(new CppIntegerData(r)).GetByteArray().toHex();
    
    Q_ASSERT(r < _curve.get_p());

    Element point;
    Botan::BigInt x, y;
    for(int i=0; i<_k; i++) {
      // x = rk + i mod p
      x = ((r*_k)+i);

      Q_ASSERT(x < _curve.get_p());

      if(SolveForY(x, point)) {
        return point;
      } 
    }

    qFatal("Failed to find point");
    return Element(new BotanECElementData(Botan::PointGFp()));
  }
 
  bool BotanECGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    if(GetPoint(a).is_zero()) return false;

    // output value = floor( x/k )
    Botan::BigInt x = GetPoint(a).get_affine_x();
   
    // x = floor(x/k)
    Botan::BigInt quotient = x / _k;

    QByteArray data(quotient.encoded_size(), 0);
    quotient.binary_encode(reinterpret_cast<byte*>(data.data()));

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

  bool BotanECGroup::IsProbablyValid() const
  {
    Botan::AutoSeeded_RNG _rng;

    return IsElement(GetGenerator()) && 
      IsIdentity(Exponentiate(GetGenerator(), GetOrder())) &&
      Botan::check_prime(_curve.get_p(), _rng) &&
      Botan::check_prime(ToBotanInt(GetOrder()), _rng);
  }

  QByteArray BotanECGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << FromBotanInt(_curve.get_p()).GetByteArray() 
      << FromBotanInt(_curve.get_a()).GetByteArray()
      << FromBotanInt(_curve.get_b()).GetByteArray();

    return out;
  }

  bool BotanECGroup::SolveForY(const Botan::BigInt &x, Element &point) const
  {
    // y^2 = x^3 + ax + b (mod p)
    const Botan::BigInt p = _curve.get_p();

    // tmp = x
    Botan::BigInt tmp = x;

    // tmp = x^2
    tmp = (x*x) % p;

    // tmp = x^2 + a
    tmp = (tmp + _curve.get_a()) % p;

    // tmp = x (x^2 + a) == (x^3 + ax)
    tmp = (tmp * x) % p;

    // tmp = x^3 + ax + b
    tmp = (tmp + _curve.get_b()) % p;
   
    // does there exist y such that (y^2 = x^3 + ax + b) mod p ?

    // jacobi symbol is 1 if tmp is a non-trivial 
    // quadratic residue mod p
    bool solved = (Botan::jacobi(tmp, _curve.get_p()) == 1);

    if(solved) {
      const Botan::BigInt y = Botan::ressol(tmp, _curve.get_p());
      Q_ASSERT(y > 0);

      point = Element(new BotanECElementData(Botan::PointGFp(_curve, x, y)));
      //Q_ASSERT(IsElement(point));
    }

    return solved;
  }

}
}
}
