#pragma once
#include <arpa/inet.h>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <utility>
#include <cstdlib>
#include <ostream>
#include <pcap.h>
//#include <unordered_map>
#include <map>
#include <tuple>
#include <string>
#include <cstring>
#define mac_strsz 17
#define mac_addrSize 6

using namespace  std;

using AP_Map = map <string,tuple<char, int,int,int,string>>;
using ST_Map = map <string,tuple<string, int,int,string>>;
/*KEY: BSSID, VALUE: PWR ,Beacons,CH,ENC,EESID*/
/*KEY: Station, VALUE: BSSID, PWR ,Frame,Probe*/

