#include "IBEUtils.hpp"

#define SIZE 160

namespace Dissent{
namespace Utils{

    int IBEUtils:: htoi(char a)
    {
       int i;
       if (a >= 'A' && a <= 'F')
       {
          i = a - 'A' + 10;
       }else if(a>='a'&&a<='f')
       {

           i=a-'a'+10;
       }else{
          i = a - '0';
       }

       return i;
     }


    void IBEUtils:: Xor(int size,const char* a,const char* b,char* xor_result)
    {

      //  qDebug()<<"a is"<<a;
       // qDebug()<<"b is"<<b;
       int i;
       int j;
       int z;
       int m;
       char result[10];

       for(m=0;m<40;m++){
           memset(result, 0, sizeof(char)*10);
           i = htoi(a[m]);
           j = htoi(b[m]);
           z = i ^ j;
           sprintf(result, "%x", z);
          // qDebug()<<"xor result z"<<result<<endl;
           strcat(xor_result, result);
       }
       // qDebug()<<xor_result;


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
