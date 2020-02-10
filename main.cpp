#include <sfdafx.h>
#include <util.h>

using namespace std;

int main(int argc, const char* argv[])
{
    //check parameter
    if(argc != 2) {
        usage();
        return -1;
        }
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* file_name = argv[1];
    pcap_t * handle = static_cast<pcap_t *>(malloc(sizeof(pcap_t *)));
    pcap_pkthdr* header= static_cast<pcap_pkthdr *>(malloc(sizeof(pcap_pkthdr)));
    const u_char* packet =static_cast<u_char *>(malloc(sizeof(u_char)));

    handle = pcap_open_offline(argv[1],errbuf);
    if (handle == nullptr){  //file open error
      fprintf(stderr, "couldn't open file %s: %s \n", file_name, errbuf);
      return -1;
    }
    AP_Map ap_map;
    ST_Map st_map;
    size_t eth_addr_outsz = 3*mac_addrSize;
    char * ap_addr = static_cast<char *>(malloc(sizeof(char)*eth_addr_outsz));
    char * st_addr = static_cast<char *>(malloc(sizeof(char)*eth_addr_outsz));
    while (true){ // main_process
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) // -1 error / -2 eof
          break;
        u_char ap_essid_len;
        string ap_essid;
        u_char st_essid_len;
        string st_essid;


//        memcpy((u_char*)(ap_essid.data()),&packet[62],ap_essid_len);

        if(htons(packet[24]+packet[25])== 0x8000)
        {
            tohex(&packet[40],sizeof(packet),ap_addr,eth_addr_outsz);
            memcpy(&ap_essid_len,&packet[61],sizeof (u_char));
            ap_essid.resize(ap_essid_len);
            memcpy((u_char*)(ap_essid.data()),&packet[62],ap_essid_len);
            if(!ap_map.count(ap_addr)&& ap_essid_len !=0)
            {
                ap_map[ap_addr] = make_tuple(0,0,0,0,"");
                get<0>(ap_map[ap_addr])=packet[18];
                get<1>(ap_map[ap_addr])+=1;
                get<2>(ap_map[ap_addr])=packet[61+ap_essid_len+13];
                get<4>(ap_map[ap_addr])=ap_essid;
            }
            else
            {
                get<0>(ap_map[ap_addr])=static_cast<char>(packet[18]);
                get<1>(ap_map[ap_addr])+=1;
            }

        }
        else if(htons(packet[24]+packet[25])==0x4000)
        {
            memcpy(&st_essid_len,&packet[49],sizeof (u_char));
            st_essid.resize(st_essid_len);
            memcpy((u_char*)(st_essid.data()),&packet[50],st_essid_len);
            tohex(&packet[34],sizeof(packet),st_addr,eth_addr_outsz);
            if(!st_map.count((st_addr)))
            {
            st_map[st_addr] = make_tuple("",0,0,"");
            get<0>(st_map[st_addr])=ap_addr;
            get<1>(st_map[st_addr])=packet[18];
            get<2>(st_map[st_addr])+=1;
            get<3>(st_map[st_addr])=st_essid;
            }
            else
            {
                get<1>(st_map[st_addr])=static_cast<char>(packet[18]);
                get<2>(st_map[st_addr])+=1;
            }


        }
        else if(htons(packet[24]+packet[25])==0x5000)
        {
            memcpy(&st_essid_len,&packet[0],sizeof (u_char));
            st_essid.resize(st_essid_len);
            memcpy((u_char*)(ap_essid.data()),&packet[50],st_essid_len);
            tohex(&packet[28],sizeof(packet),st_addr,eth_addr_outsz);
            if(!st_map.count((st_addr)))
            {
            st_map[st_addr] = make_tuple("",0,0,"");
            get<0>(st_map[st_addr])=ap_addr;
            get<1>(st_map[st_addr])=packet[18];
            get<2>(st_map[st_addr])+=1;
            get<3>(st_map[st_addr])=st_essid;
            }
            else
            {
                get<1>(st_map[st_addr])=static_cast<char>(packet[18]);
                get<2>(st_map[st_addr])+=1;
            }
        }
    }
//    printf("88:36:6c:2e:74:24 = %s",get<4>(ap_map["88:36:6C:2E:74:24"]));
    free(ap_addr);
//    free((void*)packet);
//    free((void*)handle);
    printf("BBSID \t\t   PWR \t Beacons\tCH \t ENC \t EESID \n");
    for (pair<string,tuple<char, int,int,int,string>> am: ap_map)
    {
        cout << am.first <<"  "<< (int)get<0>(am.second) <<"\t\t"<< get<1>(am.second)<<"  \t"<<get<2>(am.second)<<"\t"<<"WPA2"<<"\t"<<get<4>(am.second)<<endl;
    }
    printf("BBSID \t\t \t Station    PWR \t Frame \t Probe\n");
    for (pair<string,tuple<string, int,int,string>> sm: st_map)
    {
        cout << get<0>(sm.second) <<"  "<<sm.first
             <<"   "<< (int)get<1>(sm.second)<<"  \t"<<get<2>(sm.second)<<"\t"<<get<3>(sm.second)<<endl;
    }




    return 0;
}
