#include <util.h>

void usage() {
  printf("syntax: airodump <interface> \n");
  printf("sample: airodump mon0 \n");
}
void tohex(const u_char * in, size_t insz, char * out, size_t outsz)
{
    const u_char * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    for (; pin< in + insz; pout += 3 , pin ++)
    {
        pout[0] = hex[(*pin>>4)&0xF];
        pout[1] = hex[*pin & 0XF];
        pout[2] = ':';
        if((pout + 3 - out) > static_cast<long>(outsz)){
            break; //prevent buffer overflow
        }
    }
    pout[-1] = 0;
}
char *Fromint_Toascii(int asciiNumber)
{
    int ascnumber_count=0;
    int asctmpNum= asciiNumber;
    while(asctmpNum){
            asctmpNum/=10;
            ascnumber_count++;
    }
    char *buffer= new char[ascnumber_count+1];
    for (int i=ascnumber_count-1; i>=0; i--)
    {
        buffer[i]=(char)((asciiNumber%10)| 48);
        asciiNumber/=10;
    }
    buffer[asciiNumber]='\0';
    return buffer;
}
