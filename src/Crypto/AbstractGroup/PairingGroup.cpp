
#include "PairingElementData.hpp"
#include "PairingGroup.hpp"

namespace Dissent {
namespace Crypto {
namespace AbstractGroup {

   const char PairingGroup::_param_bytes_128[] = "type a\n"
      "q 510423550381407696080505626685710794763\n"
      "h 12\n"
      "r 42535295865117308006708802223809232897\n"
      "exp2 125\n"
      "exp1 66\n"
      "sign1 1\n"
      "sign0 1\n";

   const char PairingGroup::_param_bytes_256[] = "type a\n"
      "q 86844066927987146567678238756515930889952488503033"
      "3748302778762104249568460859\n" 
      "h 60\n"
      "r 14474011154664524427946373126085988481658748083838"
      "895805046312701737492807681\n"
      "exp2 253\n"
      "exp1 99\n"
      "sign1 1\n"
      "sign0 1\n";
     
   const char PairingGroup::_param_bytes_512[] = "type a\n"
      "q 4022342378982779129872207499461753838243809746177"
      "718013317068433116529209022064093040562289450071028"
      "3070095574559458152561261648435839696004242891736088563\n"
      "h 12\n"
      "r 3351951982485649274893506249551461531869841455148"
      "098344430890360930441007518386744200468574541725856"
      "922507964546621512713438470702986641333686907644674047\n"
      "exp2 510\n"
      "exp1 60\n"
      "sign1 -1\n"
      "sign0 -1\n";

   const char PairingGroup::_param_bytes_768[] = "type a\n"
      "q 6986331415353190208170407698081261498655987077"
      "025130081920719180000150960629849335932657950726"
      "897878035682293022593927443359270676851965091069"
      "227245916740903797609678705994380431233947094971"
      "628979495118162576165549488984143958114231\n"
      "h 72\n"
      "r 9703238076879430844681121802890640970355537606979"
      "347336000998861111320778652568522128691598231802608"
      "382892073642491565893554542606738840404262815619328"
      "806810830013442647214417265602704298571706915965441"
      "8924668965965124779777196031\n"
      "exp2 764\n"
      "exp1 594\n"
      "sign1 -1\n"
      "sign0 -1\n";

   const char PairingGroup::_param_bytes_1024[] = "type a\n"
      "q 26965397022934642815604720195284411498379428915883"
      "4273533540112716979092485575074837354618880859727251"
      "8567343546705671521136994408239078269690367170342540"
      "3176418866341821647431173031288074441276107333113389"
      "3660979645988642430177523421851207793454189094496910"
      "965683843941885568544819586125175323929311570821143\n"
      "h 24\n"
      "r 11235582092889434506501966748035171457658095381618"
      "0947305641713632074621868989614515564424533691553021"
      "6069726477794029800473747670099615945704319654309391"
      "7990174527642425686429655429703364350531711388797245"
      "5692074852495267679240634759104669913939245456040379"
      "56903493497578565356034149421882305163721315450881\n"
      "exp2 1020\n"
      "exp1 972\n"
      "sign1 -1\n"
      "sign0 1\n";

   const char PairingGroup::_param_bytes_1280[] = "type a\n"
      "q 15611898291996598622887860491046128307922893370900"
      "0572079786685256054120895100404470183591625984862772"
      "6363242093142151168707535009320681292746108198574711"
      "9913274852950012751499412114545570716838922069142267"
      "7786797689195794331352797616295938083818018791368272"
      "9298209437190787191497327877081312181656302562708692"
      "3922662670364258105373351751547859029624594327523800"
      "475014240834930696257511\n"
      "h 24\n"
      "r 65049576216652494262032752046025534616345389045416"
      "9050332444521900225503729585018625764965108270261552"
      "6513508721425629869614729205502838719775450827394633"
      "2971978553958386464580883810606544653495508621426115"
      "7444990371649143047303323401233075349241744964034470"
      "5409205988294946631238866154505467423567927344619551"
      "6344427793184408772388965631449412623435809698015835"
      "3125593368122112344063\n"
      "exp2 1275\n"
      "exp1 852\n"
      "sign1 1\n"
      "sign0 -1\n";

   const char PairingGroup::_param_bytes_1536[] = "type a\n"
      "q 7908837650834638181278507613530405682992805969821"
      "791871648933721932875816160604252195435235352229225"
      "458191264359163765710173555711670957003806542616516"
      "604325087418769845957768779128693167392420814649438"
      "419553784563991291096249465827920176494389010510149"
      "082573154424098471709447017807186976199600519297387"
      "152773179889633348563146698787940301164459292513455"
      "654335780247879894229300949414227058504663121098551"
      "961210874507359595039202358024604862291234816917294"
      "28647\n"
      "h 168\n"
      "r 4707641458830141774570540246149051001781432124893"
      "923733124365310674330842952740626306806687709660253"
      "248923371642359384351293783161708902978456275366974"
      "169241123463553479736767130433745932971679056338951"
      "440210586049994816128719920135666771722850601494136"
      "358674496681010995065147034409039866785476499581778"
      "067126892791448421763777796897583512597892436019914"
      "079961773957071365612679136556087534824204238749138"
      "072149330063904520856668070252740989459068343403151"
      "361\n"
      "exp2 1527\n"
      "exp1 385\n"
      "sign1 1\n"
      "sign0 1\n";

  PairingGroup::PairingGroup(GroupSize s) :
    _size(s)
  {
    switch(s) {
      case TESTING_128:
        _param_str = QByteArray(_param_bytes_128);
        break;
      case TESTING_256:
        _param_str = QByteArray(_param_bytes_256);
        break;
      case PRODUCTION_512:
        _param_str = QByteArray(_param_bytes_512);
        break;
      case PRODUCTION_768:
        _param_str = QByteArray(_param_bytes_768);
        break;
      case PRODUCTION_1024:
        _param_str = QByteArray(_param_bytes_1024);
        break;
      case PRODUCTION_1280:
        _param_str = QByteArray(_param_bytes_1280);
        break;
      case PRODUCTION_1536:
        _param_str = QByteArray(_param_bytes_1536);
        break;

      default:
        qFatal("Unknown parameter type");
    }

    _pairing = QSharedPointer<Pairing>(new Pairing(_param_str.constData(), _param_str.count()));

    // Maxlen = 32 kb
    const int maxlen = 1024*32;
    int ret;
    QByteArray buf(maxlen, 0);

    mpz_t p, q;
    mpz_init(p);
    mpz_init(q);
    if((ret = gmp_sscanf(_param_str, "type a q %Zd h %*Zd r %Zd", p, q)) != 2)
      qFatal("gmp_sscanf failed");

    // PBC calls the field size "q" while we
    // call it p. This is the field size of G1 and G2 in a type-A pairing.
    // The field size for GT is (field_size)^2
    if((ret = gmp_snprintf(buf.data(), buf.count(), "%Zx", p)) >= maxlen) 
      qFatal("gmp_snprintf failed");
    _field = Integer(QByteArray::fromHex(buf.left(ret)));

   // PBC calls the order "r", while we call it "q"
    if((ret = gmp_snprintf(buf.data(), buf.count(), "%Zx", q)) >= maxlen) 
      qFatal("gmp_snprintf failed");
    _order = Integer(QByteArray::fromHex(buf.left(ret)));

    mpz_clear(p);
    mpz_clear(q);

    Q_ASSERT(_pairing->isPairingPresent());

  };

  PairingGroup::PairingGroup(const PairingGroup &other) :
    _param_str(other._param_str),
    _pairing(new Pairing(_param_str.constData(), _param_str.count())),
    _order(other._order),
    _field(other._field)
  {}

  PairingGroup::~PairingGroup()
  {}

  Integer PairingGroup::RandomExponent() const
  {
    return Integer::GetRandomInteger(1, GetOrder(), false); 
  }
  
  Zr PairingGroup::IntegerToZr(const Integer &in) const
  { 
    mpz_t z;
    mpz_init(z);
    QByteArray b = in.GetByteArray().toHex();
    const char *bytes = b.constData();
    int ret;

    if((ret = gmp_sscanf(bytes, "%Zx", z)) != 1) {
      //qDebug() << "Bad string of len" << b.count() << ":" << bytes;
      //qDebug() << "Read" << ret;
      qFatal("Could not convert integer");
    }

    Zr e(*_pairing, z);
    Q_ASSERT(e.isElementPresent());

    mpz_clear(z);
    return e; 
  }

}
}
}
