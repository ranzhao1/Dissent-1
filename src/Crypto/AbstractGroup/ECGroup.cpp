
#include "ECElementData.hpp"
#include "ECGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  ECGroup::ECGroup(Integer p, Integer q, Integer a, Integer b, Integer gx, Integer gy) :
      _curve(ToCryptoInt(p), ToCryptoInt(a), ToCryptoInt(b)),
      _q(q),
      _g(ToCryptoInt(gx), ToCryptoInt(gy))
    {
      qDebug() << " p" << p.GetByteArray().toHex(); 
      qDebug() << " a" << a.GetByteArray().toHex(); 
      qDebug() << " b" << b.GetByteArray().toHex(); 
      qDebug() << "gx" << gx.GetByteArray().toHex(); 
      qDebug() << "gy" << gy.GetByteArray().toHex(); 
    };


  QSharedPointer<ECGroup> ECGroup::ProductionFixed() 
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

    return QSharedPointer<ECGroup>(new ECGroup(p, q, a, b, gx, gy));
  }

  Element ECGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new ECElementData(_curve.Add(GetPoint(a), GetPoint(b))));
  }

  Element ECGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new ECElementData(_curve.Multiply(ToCryptoInt(exp), GetPoint(a))));
  }
  
  Element ECGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    return Element(new ECElementData(_curve.CascadeMultiply(
          ToCryptoInt(e1), GetPoint(a1),
          ToCryptoInt(e2), GetPoint(a2))));
  }

  Element ECGroup::Inverse(const Element &a) const
  {
    return Element(new ECElementData(_curve.Inverse(GetPoint(a))));
  }
  
  QByteArray ECGroup::ElementToByteArray(const Element &a) const
  {
    const unsigned int nbytes = _curve.EncodedPointSize(true);
    QByteArray out(nbytes, 0);
    _curve.EncodePoint(reinterpret_cast<unsigned char*>(out.data()), GetPoint(a), true);
    return out;
  }
  
  Element ECGroup::ElementFromByteArray(const QByteArray &bytes) const 
  { 
    CryptoPP::ECPPoint point;
    _curve.DecodePoint(point, 
        reinterpret_cast<const unsigned char*>(bytes.constData()), 
        bytes.count());
    return Element(new ECElementData(point));
  }

  bool ECGroup::IsElement(const Element &a) const 
  {
    return _curve.VerifyPoint(GetPoint(a));
  }

  bool ECGroup::IsIdentity(const Element &a) const 
  {
    return (a == GetIdentity());
  }

  Integer ECGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(0, GetOrder(), false); 
  }

  Element ECGroup::RandomElement() const
  {
    return Exponentiate(GetGenerator(), RandomExponent());
  }

  CryptoPP::ECPPoint ECGroup::GetPoint(const Element &e) const
  {
    return ECElementData::GetPoint(e.GetData());
  }

  Element ECGroup::EncodeBytes(const QByteArray &) const
  {
    /*
    // We can store p bytes minus 2 bytes for padding and one more to be safe
    const int can_read = BytesPerElement();

    if(can_read < 1) qFatal("Illegal parameters");
    if(in.count() > can_read) qFatal("Cannot encode: string is too long");

    // Add initial 0xff byte and trailing 0x00 byte
    QByteArray padded;
    padded.append(0xff);
    padded.append(in.left(can_read));
    padded.append((char)0x00);
    padded.append(0xff);

    // Change byte of padded string until the
    // integer represented by the byte arry is a quadratic
    // residue. We need to be sure that every plaintext
    // message is a quadratic residue modulo p
    const int last = padded.count()-2;

    for(unsigned char pad=0x00; pad < 0xff; pad++) {
      padded[last] = pad;

      Element element(new IntegerElementData(Integer(padded)));
      if(IsElement(element)) {
        return element;
      }
    }

    qFatal("Could not encode message as quadratic residue");
    */
    return Element(new ECElementData(CryptoPP::ECPPoint()));
  }
 
  bool ECGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    QByteArray data = ElementToByteArray(a);
    if(data.count() < 3) {
      qWarning() << "Tried to decode invalid plaintext (too short):" << data.toHex();
      return false;
    }

    const unsigned char cfirst = data[0];
    const unsigned char clast = data.right(1)[0];
    if(cfirst != 0xff || clast != 0xff) {
      qWarning() << "Tried to decode invalid plaintext (bad padding)";
      return false;
    }

    out = data.mid(1, data.count()-3);
    return true;
  }

  bool ECGroup::IsProbablyValid() const
  {
    qDebug() << IsElement(GetGenerator());
    qDebug() << IsIdentity(Exponentiate(GetGenerator(), GetOrder()));
    return IsElement(GetGenerator()) && 
      IsIdentity(Exponentiate(GetGenerator(), GetOrder()));
  }

  QByteArray ECGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << FromCryptoInt(_curve.FieldSize()).GetByteArray() 
      << FromCryptoInt(_curve.GetA()).GetByteArray()
      << FromCryptoInt(_curve.GetB()).GetByteArray();

    return out;
  }

}
}
}
