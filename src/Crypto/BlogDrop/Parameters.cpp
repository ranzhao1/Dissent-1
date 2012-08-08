#include <QByteArray>

#include "Parameters.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<Parameters> Parameters::Generate() 
  {
    qFatal("Generate not yet supported");
    return QSharedPointer<Parameters>(new Parameters(Integer(), Integer()));
  }

  QSharedPointer<Parameters> Parameters::Fixed() 
  {
#ifdef DISSENT_TEST
    const QByteArray bytes_p = QByteArray::fromHex(
                               "1ADC5BAB8AA55C5B3277EC87A7383ACFDD581D8A86E71"
                               "1CE98F1690BF81122EE873C53EC2A0646074B94416CDB"
                               "FBC01FADA1C9D110DBEF1706CEBAC27F7D53C8F");
    const QByteArray bytes_g = QByteArray::fromHex(
                               "140A22002B9DC16A1F4AD9FE6CEB8548F98F7047EDE02"
                               "EEF41A0F8DDD85B25AC551137DDD3A940A33EF6889CC5"
                               "78DA0745F458AF4A9171EA189EA2A39D852C9E5");
#else
    const QByteArray bytes_p = QByteArray::fromHex(
                               "1CEB470C95CA446FBDD85B00B06D7CEC03189704005BE"
                               "DE7779B56F79057C3552BA74E7B1E9592805EB6B9FD43"
                               "09219B5EC755F0B2C8F65737D76246F4B96B5D55761DD"
                               "8EC30BCA7A15C43EC92216D595B4D718002CE32BB4453"
                               "00D151ED2C212BA411F4725D10F7AE459C67857BCE2AB"
                               "99010052AF9F685F37D1484570D35D0B");
    const QByteArray bytes_g = QByteArray::fromHex(
                               "80022675C64380BF40EC20A2681C4AD9A04CEB144D89B"
                               "9865402B25E5491C32732E330CC89D3F5C9D474B4B2EB"
                               "C7B5754A8B083432C388BA601D7BD79B371F6A2ED6A51"
                               "98DA86832DE32AC95F1B8EEEF61D1B16E4C7C84FB7AA4"
                               "1F622538B72600443E179C1A9AAA40F8E7384311CE536"
                               "1BDEBA2E1513579CC4457BFD3167B1B");
#endif

    const Integer p(bytes_p);
    const Integer g(bytes_g);

    if(g.Pow((p-1)/2, g) == 1)
      qFatal("g does not generate G*_p");

    return QSharedPointer<Parameters>(new Parameters(p, g.Pow(2, p)));
  }

  QSharedPointer<Parameters> Parameters::Zero() 
  {
    return QSharedPointer<Parameters>(new Parameters()); 
  }

  Parameters::Parameters() {}

  Parameters::Parameters(const Integer p, const Integer g):
    _p(p),
    _q((p-1)/2),
    _g(g),
    _p_sqrt((p+1)/4) 
  {
    Q_ASSERT(AreProbablyValid());
  }

  Integer Parameters::RandomExponent() const
  {
    return Integer::GetRandomInteger(0, _q, false); 
  }

  Integer Parameters::RandomElement() const
  {
    return _g.Pow(RandomExponent(), _p);
  }

  bool Parameters::IsElement(const Integer &i) const
  {
    return (i.Pow(_q, _p) == 1);
  }

  bool Parameters::AreProbablyValid() const 
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
}
}
}
