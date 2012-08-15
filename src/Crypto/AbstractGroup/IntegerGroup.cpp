
#include "IntegerElementData.hpp"
#include "IntegerGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

  IntegerGroup::IntegerGroup(Integer p, Integer g) :
      _p(p), 
      _q((p-1)/2), 
      _g(g) 
    {};

  QSharedPointer<IntegerGroup> IntegerGroup::Generate(int) 
  {
    qFatal("Generate not yet supported");
    return QSharedPointer<IntegerGroup>(new IntegerGroup(Integer(), Integer()));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::TestingFixed() 
  {
    const QByteArray bytes_p = QByteArray::fromHex(
                               "0x1ADC5BAB8AA55C5B3277EC87A7383ACFDD581D8A86E71"
                               "1CE98F1690BF81122EE873C53EC2A0646074B94416CDB"
                               "FBC01FADA1C9D110DBEF1706CEBAC27F7D53C8F");
    const QByteArray bytes_g = QByteArray::fromHex(
                               "0x140A22002B9DC16A1F4AD9FE6CEB8548F98F7047EDE02"
                               "EEF41A0F8DDD85B25AC551137DDD3A940A33EF6889CC5"
                               "78DA0745F458AF4A9171EA189EA2A39D852C9E5");

    const Integer p(bytes_p);
    const Integer g(bytes_g);

    if(g.Pow((p-1)/2, g) == 1)
      qFatal("g does not generate G*_p");

    return QSharedPointer<IntegerGroup>(new IntegerGroup(p, g.Pow(2, p)));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::ProductionFixed() 
  {
    const QByteArray bytes_p = QByteArray::fromHex(
                               "0x1CEB470C95CA446FBDD85B00B06D7CEC03189704005BE"
                               "DE7779B56F79057C3552BA74E7B1E9592805EB6B9FD43"
                               "09219B5EC755F0B2C8F65737D76246F4B96B5D55761DD"
                               "8EC30BCA7A15C43EC92216D595B4D718002CE32BB4453"
                               "00D151ED2C212BA411F4725D10F7AE459C67857BCE2AB"
                               "99010052AF9F685F37D1484570D35D0B");
    const QByteArray bytes_g = QByteArray::fromHex(
                               "0x80022675C64380BF40EC20A2681C4AD9A04CEB144D89B"
                               "9865402B25E5491C32732E330CC89D3F5C9D474B4B2EB"
                               "C7B5754A8B083432C388BA601D7BD79B371F6A2ED6A51"
                               "98DA86832DE32AC95F1B8EEEF61D1B16E4C7C84FB7AA4"
                               "1F622538B72600443E179C1A9AAA40F8E7384311CE536"
                               "1BDEBA2E1513579CC4457BFD3167B1B");

    const Integer p(bytes_p);
    const Integer g(bytes_g);

    if(g.Pow((p-1)/2, g) == 1)
      qFatal("g does not generate G*_p");

    return QSharedPointer<IntegerGroup>(new IntegerGroup(p, g.Pow(2, p)));
  }

  QSharedPointer<IntegerGroup> IntegerGroup::Zero() 
  {
    return QSharedPointer<IntegerGroup>(new IntegerGroup(Integer(0), Integer(0))); 
  }


  Element IntegerGroup::Multiply(const Element &a, const Element &b) const
  {
    return Element(new IntegerElementData((GetInteger(a).MultiplyMod(GetInteger(b), _p)))); 
  }

  Element IntegerGroup::Exponentiate(const Element &a, const Integer &exp) const
  {
    return Element(new IntegerElementData(GetInteger(a).Pow(exp, _p))); 
  }
  
  Element IntegerGroup::CascadeExponentiate(const Element &a1, const Integer &e1,
      const Element &a2, const Integer &e2) const
  {
    return Element(new IntegerElementData(
          _p.PowCascade(GetInteger(a1), e1, GetInteger(a2), e2)));
  }

  Element IntegerGroup::Inverse(const Element &a) const
  {
    return Element(new IntegerElementData(GetInteger(a).ModInverse(_p)));
  }
  
  QByteArray IntegerGroup::ElementToByteArray(const Element &a) const
  {
    return GetInteger(a).GetByteArray();
  }
  
  Element IntegerGroup::ElementFromByteArray(const QByteArray &bytes) const 
  {
    return Element(new IntegerElementData(Integer(bytes)));
  }

  bool IntegerGroup::IsElement(const Element &a) const 
  {
    return (GetInteger(a).Pow(_q, _p) == 1);
  }

  bool IntegerGroup::IsIdentity(const Element &a) const 
  {
    return (GetInteger(a) == 1);
  }

  Integer IntegerGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(0, _q, false); 
  }

  Element IntegerGroup::RandomElement() const
  {
    return Element(new IntegerElementData(_g.Pow(RandomExponent(), _p)));
  }

  Integer IntegerGroup::GetInteger(const Element &e) const
  {
    return IntegerElementData::GetInteger(e.GetData());
  }

  Element IntegerGroup::EncodeBytes(const QByteArray &in) const
  {
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
    return Element(new IntegerElementData(Integer(1)));
  }
 
  bool IntegerGroup::DecodeBytes(const Element &a, QByteArray &out) const
  {
    QByteArray data = a.GetByteArray();
    if(data.count() < 3) {
      qWarning() << "Tried to decode invalid plaintext (too short):" << a.GetByteArray().toHex();
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

  bool IntegerGroup::IsProbablyValid() const
  {
    // g != -1, 0, 1
    if(_g == 0 || _g == 1 || _g == Integer(-1).Modulo(_p))
      return false;

    qDebug() << _g.Pow(_q, _p).GetByteArray();

    // g^q = 1
    if(_g.Pow(_q, _p) != 1)
      return false;

    return true;
  }

  QByteArray IntegerGroup::GetByteArray() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << _p << _g << _q;

    return out;
  }

}
}
}
