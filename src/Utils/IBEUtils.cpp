#include "IBEUtils.hpp"

#define SIZE 160

namespace Dissent{
namespace Utils{

QByteArray  IBEUtils::calculateXor(const QByteArray& data, const QByteArray& key)
{
 if(key.isEmpty())
   return data;

 QByteArray result;
 for(int i = 0 , j = 0; i < data.length(); ++i , ++j)
 {
   if(j == key.length())
     j = 0;// repeat the key if key.length() < data.length()
   result.append(data.at(i) ^ key.at(j));
 }
 return result;
}


    Integer IBEUtils::HashToZr(Integer GroupOrder,QByteArray &data)
    {
        Hash *hash=CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();

        QByteArray DataHash=hash->ComputeHash(data);
        Integer i=Integer(DataHash);
        return i%GroupOrder;

    }

    void IBEUtils::Randn(char *sigma)
    {

          int i;
          int unit;
          char tempr[10];
          memset(sigma, 0, sizeof(char)*SIZE);//Clear the memory of sigma

          for (i = 0; i < 40; i++){
          unit = rand() % 16;
          sprintf(tempr, "%x", unit);
          strcat(sigma, tempr);

          }

    }




}
}
