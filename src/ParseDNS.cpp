#include "ParseDNS.h"

#include <bitset>
#include <ctype.h>
#include <netinet/in.h>
#include <sparsehash/dense_hash_set>
#include <string.h>

#include "Config.h"
#include "StringHash.h"

#define UNUSED(x) (void(x))

using namespace google;
using namespace std;

// NOTE: Variable name must be globally unique for the template
extern const uint8_t dnsKey[16];
const uint8_t dnsKey[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6 };
typedef dense_hash_set<const char *, StringHash<dnsKey>, StringEqual>
        ValidTLDSet;

static bitset<(1 << 16)> validTypes;
static bitset<(1 << 16)> validClasses;
static ValidTLDSet validTLDs;

template<size_t N>
static void setBitsInRange(bitset<N> set, size_t start, size_t end) {
  for(size_t i = start; i <= end; i++) {
    set[i] = true;
  }
}

void dnsParseInit() {
  // Based on http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
  // Select whether or not to count obsolete or experimental types as valid by
  // setting the OBSOLETE_TYPES_VALID and EXPERIMENTAL_TYPES_VALID configuration
  // variables
  setBitsInRange<(1 << 16)>(validTypes, 1, 2);
  setBitsInRange<(1 << 16)>(validTypes, 5, 6);
  setBitsInRange<(1 << 16)>(validTypes, 11, 29);
  setBitsInRange<(1 << 16)>(validTypes, 31, 37);
  setBitsInRange<(1 << 16)>(validTypes, 39, 52);
  setBitsInRange<(1 << 16)>(validTypes, 55, 59);
  setBitsInRange<(1 << 16)>(validTypes, 99, 109);
  setBitsInRange<(1 << 16)>(validTypes, 249, 253);
  setBitsInRange<(1 << 16)>(validTypes, 255, 257);
  setBitsInRange<(1 << 16)>(validTypes, 32768, 32769);

  if(OBSOLETE_TYPES_VALID) {
    setBitsInRange<(1 << 16)>(validTypes, 3, 4);
    validTypes.set(30);
    validTypes.set(38);
    validTypes.set(254);
  }

  if(EXPERIMENTAL_TYPES_VALID) {
    setBitsInRange<(1 << 16)>(validTypes, 7, 10);
  }

  // Based on http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
  validClasses.set(1);
  validClasses.set(3);
  validClasses.set(4);
  validClasses.set(254);
  validClasses.set(255);

  // Based on http://data.iana.org/TLD/tlds-alpha-by-domain.txt
  // Including upper and lower case in the hash table so I can ignore having to
  // force each domain name into upper case
  validTLDs.set_empty_key(NULL);
  validTLDs.insert("ac"); validTLDs.insert("AC");
  validTLDs.insert("ad"); validTLDs.insert("AD");
  validTLDs.insert("ae"); validTLDs.insert("AE");
  validTLDs.insert("aero"); validTLDs.insert("AERO");
  validTLDs.insert("af"); validTLDs.insert("AF");
  validTLDs.insert("ag"); validTLDs.insert("AG");
  validTLDs.insert("ai"); validTLDs.insert("AI");
  validTLDs.insert("al"); validTLDs.insert("AL");
  validTLDs.insert("am"); validTLDs.insert("AM");
  validTLDs.insert("an"); validTLDs.insert("AN");
  validTLDs.insert("ao"); validTLDs.insert("AO");
  validTLDs.insert("aq"); validTLDs.insert("AQ");
  validTLDs.insert("ar"); validTLDs.insert("AR");
  validTLDs.insert("arpa"); validTLDs.insert("ARPA");
  validTLDs.insert("as"); validTLDs.insert("AS");
  validTLDs.insert("asia"); validTLDs.insert("ASIA");
  validTLDs.insert("at"); validTLDs.insert("AT");
  validTLDs.insert("au"); validTLDs.insert("AU");
  validTLDs.insert("aw"); validTLDs.insert("AW");
  validTLDs.insert("ax"); validTLDs.insert("AX");
  validTLDs.insert("az"); validTLDs.insert("AZ");
  validTLDs.insert("ba"); validTLDs.insert("BA");
  validTLDs.insert("bb"); validTLDs.insert("BB");
  validTLDs.insert("bd"); validTLDs.insert("BD");
  validTLDs.insert("be"); validTLDs.insert("BE");
  validTLDs.insert("bf"); validTLDs.insert("BF");
  validTLDs.insert("bg"); validTLDs.insert("BG");
  validTLDs.insert("bh"); validTLDs.insert("BH");
  validTLDs.insert("bi"); validTLDs.insert("BI");
  validTLDs.insert("biz"); validTLDs.insert("BIZ");
  validTLDs.insert("bj"); validTLDs.insert("BJ");
  validTLDs.insert("bm"); validTLDs.insert("BM");
  validTLDs.insert("bn"); validTLDs.insert("BN");
  validTLDs.insert("bo"); validTLDs.insert("BO");
  validTLDs.insert("br"); validTLDs.insert("BR");
  validTLDs.insert("bs"); validTLDs.insert("BS");
  validTLDs.insert("bt"); validTLDs.insert("BT");
  validTLDs.insert("bv"); validTLDs.insert("BV");
  validTLDs.insert("bw"); validTLDs.insert("BW");
  validTLDs.insert("by"); validTLDs.insert("BY");
  validTLDs.insert("bz"); validTLDs.insert("BZ");
  validTLDs.insert("ca"); validTLDs.insert("CA");
  validTLDs.insert("cat"); validTLDs.insert("CAT");
  validTLDs.insert("cc"); validTLDs.insert("CC");
  validTLDs.insert("cd"); validTLDs.insert("CD");
  validTLDs.insert("cf"); validTLDs.insert("CF");
  validTLDs.insert("cg"); validTLDs.insert("CG");
  validTLDs.insert("ch"); validTLDs.insert("CH");
  validTLDs.insert("ci"); validTLDs.insert("CI");
  validTLDs.insert("ck"); validTLDs.insert("CK");
  validTLDs.insert("cl"); validTLDs.insert("CL");
  validTLDs.insert("cm"); validTLDs.insert("CM");
  validTLDs.insert("cn"); validTLDs.insert("CN");
  validTLDs.insert("co"); validTLDs.insert("CO");
  validTLDs.insert("com"); validTLDs.insert("COM");
  validTLDs.insert("coop"); validTLDs.insert("COOP");
  validTLDs.insert("cr"); validTLDs.insert("CR");
  validTLDs.insert("cu"); validTLDs.insert("CU");
  validTLDs.insert("cv"); validTLDs.insert("CV");
  validTLDs.insert("cw"); validTLDs.insert("CW");
  validTLDs.insert("cx"); validTLDs.insert("CX");
  validTLDs.insert("cy"); validTLDs.insert("CY");
  validTLDs.insert("cz"); validTLDs.insert("CZ");
  validTLDs.insert("de"); validTLDs.insert("DE");
  validTLDs.insert("dj"); validTLDs.insert("DJ");
  validTLDs.insert("dk"); validTLDs.insert("DK");
  validTLDs.insert("dm"); validTLDs.insert("DM");
  validTLDs.insert("do"); validTLDs.insert("DO");
  validTLDs.insert("dz"); validTLDs.insert("DZ");
  validTLDs.insert("ec"); validTLDs.insert("EC");
  validTLDs.insert("edu"); validTLDs.insert("EDU");
  validTLDs.insert("ee"); validTLDs.insert("EE");
  validTLDs.insert("eg"); validTLDs.insert("EG");
  validTLDs.insert("er"); validTLDs.insert("ER");
  validTLDs.insert("es"); validTLDs.insert("ES");
  validTLDs.insert("et"); validTLDs.insert("ET");
  validTLDs.insert("eu"); validTLDs.insert("EU");
  validTLDs.insert("fi"); validTLDs.insert("FI");
  validTLDs.insert("fj"); validTLDs.insert("FJ");
  validTLDs.insert("fk"); validTLDs.insert("FK");
  validTLDs.insert("fm"); validTLDs.insert("FM");
  validTLDs.insert("fo"); validTLDs.insert("FO");
  validTLDs.insert("fr"); validTLDs.insert("FR");
  validTLDs.insert("ga"); validTLDs.insert("GA");
  validTLDs.insert("gb"); validTLDs.insert("GB");
  validTLDs.insert("gd"); validTLDs.insert("GD");
  validTLDs.insert("ge"); validTLDs.insert("GE");
  validTLDs.insert("gf"); validTLDs.insert("GF");
  validTLDs.insert("gg"); validTLDs.insert("GG");
  validTLDs.insert("gh"); validTLDs.insert("GH");
  validTLDs.insert("gi"); validTLDs.insert("GI");
  validTLDs.insert("gl"); validTLDs.insert("GL");
  validTLDs.insert("gm"); validTLDs.insert("GM");
  validTLDs.insert("gn"); validTLDs.insert("GN");
  validTLDs.insert("gov"); validTLDs.insert("GOV");
  validTLDs.insert("gp"); validTLDs.insert("GP");
  validTLDs.insert("gq"); validTLDs.insert("GQ");
  validTLDs.insert("gr"); validTLDs.insert("GR");
  validTLDs.insert("gs"); validTLDs.insert("GS");
  validTLDs.insert("gt"); validTLDs.insert("GT");
  validTLDs.insert("gu"); validTLDs.insert("GU");
  validTLDs.insert("gw"); validTLDs.insert("GW");
  validTLDs.insert("gy"); validTLDs.insert("GY");
  validTLDs.insert("hk"); validTLDs.insert("HK");
  validTLDs.insert("hm"); validTLDs.insert("HM");
  validTLDs.insert("hn"); validTLDs.insert("HN");
  validTLDs.insert("hr"); validTLDs.insert("HR");
  validTLDs.insert("ht"); validTLDs.insert("HT");
  validTLDs.insert("hu"); validTLDs.insert("HU");
  validTLDs.insert("id"); validTLDs.insert("ID");
  validTLDs.insert("ie"); validTLDs.insert("IE");
  validTLDs.insert("il"); validTLDs.insert("IL");
  validTLDs.insert("im"); validTLDs.insert("IM");
  validTLDs.insert("in"); validTLDs.insert("IN");
  validTLDs.insert("info"); validTLDs.insert("INFO");
  validTLDs.insert("int"); validTLDs.insert("INT");
  validTLDs.insert("io"); validTLDs.insert("IO");
  validTLDs.insert("iq"); validTLDs.insert("IQ");
  validTLDs.insert("ir"); validTLDs.insert("IR");
  validTLDs.insert("is"); validTLDs.insert("IS");
  validTLDs.insert("it"); validTLDs.insert("IT");
  validTLDs.insert("je"); validTLDs.insert("JE");
  validTLDs.insert("jm"); validTLDs.insert("JM");
  validTLDs.insert("jo"); validTLDs.insert("JO");
  validTLDs.insert("jobs"); validTLDs.insert("JOBS");
  validTLDs.insert("jp"); validTLDs.insert("JP");
  validTLDs.insert("ke"); validTLDs.insert("KE");
  validTLDs.insert("kg"); validTLDs.insert("KG");
  validTLDs.insert("kh"); validTLDs.insert("KH");
  validTLDs.insert("ki"); validTLDs.insert("KI");
  validTLDs.insert("km"); validTLDs.insert("KM");
  validTLDs.insert("kn"); validTLDs.insert("KN");
  validTLDs.insert("kp"); validTLDs.insert("KP");
  validTLDs.insert("kr"); validTLDs.insert("KR");
  validTLDs.insert("kw"); validTLDs.insert("KW");
  validTLDs.insert("ky"); validTLDs.insert("KY");
  validTLDs.insert("kz"); validTLDs.insert("KZ");
  validTLDs.insert("la"); validTLDs.insert("LA");
  validTLDs.insert("lb"); validTLDs.insert("LB");
  validTLDs.insert("lc"); validTLDs.insert("LC");
  validTLDs.insert("li"); validTLDs.insert("LI");
  validTLDs.insert("lk"); validTLDs.insert("LK");
  validTLDs.insert("lr"); validTLDs.insert("LR");
  validTLDs.insert("ls"); validTLDs.insert("LS");
  validTLDs.insert("lt"); validTLDs.insert("LT");
  validTLDs.insert("lu"); validTLDs.insert("LU");
  validTLDs.insert("lv"); validTLDs.insert("LV");
  validTLDs.insert("ly"); validTLDs.insert("LY");
  validTLDs.insert("ma"); validTLDs.insert("MA");
  validTLDs.insert("mc"); validTLDs.insert("MC");
  validTLDs.insert("md"); validTLDs.insert("MD");
  validTLDs.insert("me"); validTLDs.insert("ME");
  validTLDs.insert("mg"); validTLDs.insert("MG");
  validTLDs.insert("mh"); validTLDs.insert("MH");
  validTLDs.insert("mil"); validTLDs.insert("MIL");
  validTLDs.insert("mk"); validTLDs.insert("MK");
  validTLDs.insert("ml"); validTLDs.insert("ML");
  validTLDs.insert("mm"); validTLDs.insert("MM");
  validTLDs.insert("mn"); validTLDs.insert("MN");
  validTLDs.insert("mo"); validTLDs.insert("MO");
  validTLDs.insert("mobi"); validTLDs.insert("MOBI");
  validTLDs.insert("mp"); validTLDs.insert("MP");
  validTLDs.insert("mq"); validTLDs.insert("MQ");
  validTLDs.insert("mr"); validTLDs.insert("MR");
  validTLDs.insert("ms"); validTLDs.insert("MS");
  validTLDs.insert("mt"); validTLDs.insert("MT");
  validTLDs.insert("mu"); validTLDs.insert("MU");
  validTLDs.insert("museum"); validTLDs.insert("MUSEUM");
  validTLDs.insert("mv"); validTLDs.insert("MV");
  validTLDs.insert("mw"); validTLDs.insert("MW");
  validTLDs.insert("mx"); validTLDs.insert("MX");
  validTLDs.insert("my"); validTLDs.insert("MY");
  validTLDs.insert("mz"); validTLDs.insert("MZ");
  validTLDs.insert("na"); validTLDs.insert("NA");
  validTLDs.insert("name"); validTLDs.insert("NAME");
  validTLDs.insert("nc"); validTLDs.insert("NC");
  validTLDs.insert("ne"); validTLDs.insert("NE");
  validTLDs.insert("net"); validTLDs.insert("NET");
  validTLDs.insert("nf"); validTLDs.insert("NF");
  validTLDs.insert("ng"); validTLDs.insert("NG");
  validTLDs.insert("ni"); validTLDs.insert("NI");
  validTLDs.insert("nl"); validTLDs.insert("NL");
  validTLDs.insert("no"); validTLDs.insert("NO");
  validTLDs.insert("np"); validTLDs.insert("NP");
  validTLDs.insert("nr"); validTLDs.insert("NR");
  validTLDs.insert("nu"); validTLDs.insert("NU");
  validTLDs.insert("nz"); validTLDs.insert("NZ");
  validTLDs.insert("om"); validTLDs.insert("OM");
  validTLDs.insert("org"); validTLDs.insert("ORG");
  validTLDs.insert("pa"); validTLDs.insert("PA");
  validTLDs.insert("pe"); validTLDs.insert("PE");
  validTLDs.insert("pf"); validTLDs.insert("PF");
  validTLDs.insert("pg"); validTLDs.insert("PG");
  validTLDs.insert("ph"); validTLDs.insert("PH");
  validTLDs.insert("pk"); validTLDs.insert("PK");
  validTLDs.insert("pl"); validTLDs.insert("PL");
  validTLDs.insert("pm"); validTLDs.insert("PM");
  validTLDs.insert("pn"); validTLDs.insert("PN");
  validTLDs.insert("post"); validTLDs.insert("POST");
  validTLDs.insert("pr"); validTLDs.insert("PR");
  validTLDs.insert("pro"); validTLDs.insert("PRO");
  validTLDs.insert("ps"); validTLDs.insert("PS");
  validTLDs.insert("pt"); validTLDs.insert("PT");
  validTLDs.insert("pw"); validTLDs.insert("PW");
  validTLDs.insert("py"); validTLDs.insert("PY");
  validTLDs.insert("qa"); validTLDs.insert("QA");
  validTLDs.insert("re"); validTLDs.insert("RE");
  validTLDs.insert("ro"); validTLDs.insert("RO");
  validTLDs.insert("rs"); validTLDs.insert("RS");
  validTLDs.insert("ru"); validTLDs.insert("RU");
  validTLDs.insert("rw"); validTLDs.insert("RW");
  validTLDs.insert("sa"); validTLDs.insert("SA");
  validTLDs.insert("sb"); validTLDs.insert("SB");
  validTLDs.insert("sc"); validTLDs.insert("SC");
  validTLDs.insert("sd"); validTLDs.insert("SD");
  validTLDs.insert("se"); validTLDs.insert("SE");
  validTLDs.insert("sg"); validTLDs.insert("SG");
  validTLDs.insert("sh"); validTLDs.insert("SH");
  validTLDs.insert("si"); validTLDs.insert("SI");
  validTLDs.insert("sj"); validTLDs.insert("SJ");
  validTLDs.insert("sk"); validTLDs.insert("SK");
  validTLDs.insert("sl"); validTLDs.insert("SL");
  validTLDs.insert("sm"); validTLDs.insert("SM");
  validTLDs.insert("sn"); validTLDs.insert("SN");
  validTLDs.insert("so"); validTLDs.insert("SO");
  validTLDs.insert("sr"); validTLDs.insert("SR");
  validTLDs.insert("st"); validTLDs.insert("ST");
  validTLDs.insert("su"); validTLDs.insert("SU");
  validTLDs.insert("sv"); validTLDs.insert("SV");
  validTLDs.insert("sx"); validTLDs.insert("SX");
  validTLDs.insert("sy"); validTLDs.insert("SY");
  validTLDs.insert("sz"); validTLDs.insert("SZ");
  validTLDs.insert("tc"); validTLDs.insert("TC");
  validTLDs.insert("td"); validTLDs.insert("TD");
  validTLDs.insert("tel"); validTLDs.insert("TEL");
  validTLDs.insert("tf"); validTLDs.insert("TF");
  validTLDs.insert("tg"); validTLDs.insert("TG");
  validTLDs.insert("th"); validTLDs.insert("TH");
  validTLDs.insert("tj"); validTLDs.insert("TJ");
  validTLDs.insert("tk"); validTLDs.insert("TK");
  validTLDs.insert("tl"); validTLDs.insert("TL");
  validTLDs.insert("tm"); validTLDs.insert("TM");
  validTLDs.insert("tn"); validTLDs.insert("TN");
  validTLDs.insert("to"); validTLDs.insert("TO");
  validTLDs.insert("tp"); validTLDs.insert("TP");
  validTLDs.insert("tr"); validTLDs.insert("TR");
  validTLDs.insert("travel"); validTLDs.insert("TRAVEL");
  validTLDs.insert("tt"); validTLDs.insert("TT");
  validTLDs.insert("tv"); validTLDs.insert("TV");
  validTLDs.insert("tw"); validTLDs.insert("TW");
  validTLDs.insert("tz"); validTLDs.insert("TZ");
  validTLDs.insert("ua"); validTLDs.insert("UA");
  validTLDs.insert("ug"); validTLDs.insert("UG");
  validTLDs.insert("uk"); validTLDs.insert("UK");
  validTLDs.insert("us"); validTLDs.insert("US");
  validTLDs.insert("uy"); validTLDs.insert("UY");
  validTLDs.insert("uz"); validTLDs.insert("UZ");
  validTLDs.insert("va"); validTLDs.insert("VA");
  validTLDs.insert("vc"); validTLDs.insert("VC");
  validTLDs.insert("ve"); validTLDs.insert("VE");
  validTLDs.insert("vg"); validTLDs.insert("VG");
  validTLDs.insert("vi"); validTLDs.insert("VI");
  validTLDs.insert("vn"); validTLDs.insert("VN");
  validTLDs.insert("vu"); validTLDs.insert("VU");
  validTLDs.insert("wf"); validTLDs.insert("WF");
  validTLDs.insert("ws"); validTLDs.insert("WS");
  validTLDs.insert("xn--0zwm56d"); validTLDs.insert("XN--0ZWM56D");
  validTLDs.insert("xn--11b5bs3a9aj6g"); validTLDs.insert("XN--11B5BS3A9AJ6G");
  validTLDs.insert("xn--3e0b707e"); validTLDs.insert("XN--3E0B707E");
  validTLDs.insert("xn--45brj9c"); validTLDs.insert("XN--45BRJ9C");
  validTLDs.insert("xn--80akhbyknj4f"); validTLDs.insert("XN--80AKHBYKNJ4F");
  validTLDs.insert("xn--80ao21a"); validTLDs.insert("XN--80AO21A");
  validTLDs.insert("xn--90a3ac"); validTLDs.insert("XN--90A3AC");
  validTLDs.insert("xn--9t4b11yi5a"); validTLDs.insert("XN--9T4B11YI5A");
  validTLDs.insert("xn--clchc0ea0b2g2a9gcd"); validTLDs.insert("XN--CLCHC0EA0B2G2A9GCD");
  validTLDs.insert("xn--deba0ad"); validTLDs.insert("XN--DEBA0AD");
  validTLDs.insert("xn--fiqs8s"); validTLDs.insert("XN--FIQS8S");
  validTLDs.insert("xn--fiqz9s"); validTLDs.insert("XN--FIQZ9S");
  validTLDs.insert("xn--fpcrj9c3d"); validTLDs.insert("XN--FPCRJ9C3D");
  validTLDs.insert("xn--fzc2c9e2c"); validTLDs.insert("XN--FZC2C9E2C");
  validTLDs.insert("xn--g6w251d"); validTLDs.insert("XN--G6W251D");
  validTLDs.insert("xn--gecrj9c"); validTLDs.insert("XN--GECRJ9C");
  validTLDs.insert("xn--h2brj9c"); validTLDs.insert("XN--H2BRJ9C");
  validTLDs.insert("xn--hgbk6aj7f53bba"); validTLDs.insert("XN--HGBK6AJ7F53BBA");
  validTLDs.insert("xn--hlcj6aya9esc7a"); validTLDs.insert("XN--HLCJ6AYA9ESC7A");
  validTLDs.insert("xn--j1amh"); validTLDs.insert("XN--J1AMH");
  validTLDs.insert("xn--j6w193g"); validTLDs.insert("XN--J6W193G");
  validTLDs.insert("xn--jxalpdlp"); validTLDs.insert("XN--JXALPDLP");
  validTLDs.insert("xn--kgbechtv"); validTLDs.insert("XN--KGBECHTV");
  validTLDs.insert("xn--kprw13d"); validTLDs.insert("XN--KPRW13D");
  validTLDs.insert("xn--kpry57d"); validTLDs.insert("XN--KPRY57D");
  validTLDs.insert("xn--lgbbat1ad8j"); validTLDs.insert("XN--LGBBAT1AD8J");
  validTLDs.insert("xn--mgb9awbf"); validTLDs.insert("XN--MGB9AWBF");
  validTLDs.insert("xn--mgbaam7a8h"); validTLDs.insert("XN--MGBAAM7A8H");
  validTLDs.insert("xn--mgbayh7gpa"); validTLDs.insert("XN--MGBAYH7GPA");
  validTLDs.insert("xn--mgbbh1a71e"); validTLDs.insert("XN--MGBBH1A71E");
  validTLDs.insert("xn--mgbc0a9azcg"); validTLDs.insert("XN--MGBC0A9AZCG");
  validTLDs.insert("xn--mgberp4a5d4ar"); validTLDs.insert("XN--MGBERP4A5D4AR");
  validTLDs.insert("xn--mgbx4cd0ab"); validTLDs.insert("XN--MGBX4CD0AB");
  validTLDs.insert("xn--o3cw4h"); validTLDs.insert("XN--O3CW4H");
  validTLDs.insert("xn--ogbpf8fl"); validTLDs.insert("XN--OGBPF8FL");
  validTLDs.insert("xn--p1ai"); validTLDs.insert("XN--P1AI");
  validTLDs.insert("xn--pgbs0dh"); validTLDs.insert("XN--PGBS0DH");
  validTLDs.insert("xn--s9brj9c"); validTLDs.insert("XN--S9BRJ9C");
  validTLDs.insert("xn--wgbh1c"); validTLDs.insert("XN--WGBH1C");
  validTLDs.insert("xn--wgbl6a"); validTLDs.insert("XN--WGBL6A");
  validTLDs.insert("xn--xkc2al3hye2a"); validTLDs.insert("XN--XKC2AL3HYE2A");
  validTLDs.insert("xn--xkc2dl3a5ee0h"); validTLDs.insert("XN--XKC2DL3A5EE0H");
  validTLDs.insert("xn--yfro4i67o"); validTLDs.insert("XN--YFRO4I67O");
  validTLDs.insert("xn--ygbi2ammx"); validTLDs.insert("XN--YGBI2AMMX");
  validTLDs.insert("xn--zckzah"); validTLDs.insert("XN--ZCKZAH");
  validTLDs.insert("xxx"); validTLDs.insert("XXX");
  validTLDs.insert("ye"); validTLDs.insert("YE");
  validTLDs.insert("yt"); validTLDs.insert("YT");
  validTLDs.insert("za"); validTLDs.insert("ZA");
  validTLDs.insert("zm"); validTLDs.insert("ZM");
  validTLDs.insert("zw"); validTLDs.insert("ZW");
}

#define HAS_ENOUGH(dStart,dEnd,size) (((dStart) + (size)) <= dEnd)

static int getLabelSize(const uint8_t *dStart, const uint8_t *dEnd,
                        bool isRDATA) {
  if(!HAS_ENOUGH(dStart, dEnd, 1)) {
    return -1;
  }

  uint8_t size = *dStart;

  if(isRDATA && (size & INDIR_MASK) == EDNS0_MASK) {
    if((size & ~INDIR_MASK) != EDNS0_ELT_BITLABEL) {
      return -1;
    }

    if(!HAS_ENOUGH(dStart, dEnd, 2)) {
      return -1;
    }

    int bitLen = *(dStart + 1);
    if(bitLen == 0) {
      bitLen = 256;
    }

    return ((bitLen + 7) / 8) + 1;
  } else if(size > 63) {
    return -1;
  }

  return size;
}

static int getDomainName(string& full, list<string>& parts, const uint8_t *dStart, const uint8_t *dEnd,
                         bool isRDATA) {
  const uint8_t *dCur = dStart;

  if(!HAS_ENOUGH(dCur, dEnd, 1)) {
    return -1;
  }

  int labelSize;
  int consumed = 0;
  while((labelSize = getLabelSize(dCur, dEnd, isRDATA)) > 0) {
    if((consumed + labelSize) > MAXDNAME ||
       !HAS_ENOUGH(dCur, dEnd, labelSize + 1)) {
      return -1;
    }

    string part;
    part.reserve(labelSize);
    full.reserve(full.size() + labelSize + 1);

    // Copying the label, but checking for unexpected NULL character(s) in the
    // middle of a domain name.
    for(int i = 0; i < labelSize; i++) {
      char c = *(dCur + 1 + i);
      if(iscntrl(c) || isspace(c)) {
        char value[16];
        sprintf(value, "<%02X>", c);
        part += value;
      } else {
        part += tolower(c);
      }
    }

    full += part + ".";
    parts.push_back(part);

    dCur += labelSize + 1;
    consumed += labelSize + 1;
  }

  if(labelSize == 0) {
    if(consumed == 0) {
      full = ".";
      parts.push_back(".");
    }
    consumed++;
  } else {
    return -1;
  }

  return consumed;
}

int dnsParseID(const uint8_t *data, uint32_t size) {
  int id = -1;

  if(size >= 2) {
    id = ntohs(*((uint16_t *)data));
  }

  return id;
}

int dnsParseResponse(const uint8_t *data, uint32_t size) {
  HEADER header;
  memcpy(&header, data, sizeof(header)); 
  return DNS_RCODE(&header); 
}

int dnsParseQuery(DNSQuery *query, const uint8_t *data, uint32_t size) {
  const uint8_t *dCur = data;
  const uint8_t *dEnd = data + size;

  // Skip processing entirely
  if(query->error == DNS_ERR_FORMAT_ERROR ||
     query->error == DNS_ERR_SERVER_FAILURE) {
    return 0;
  }

  // Header
  memcpy(&query->header, dCur, sizeof(query->header));
  query->header.id = ntohs(query->header.id);
  query->header.qdcount = ntohs(query->header.qdcount);
  query->header.ancount = ntohs(query->header.ancount);
  query->header.nscount = ntohs(query->header.nscount);
  query->header.arcount = ntohs(query->header.arcount);
  dCur += sizeof(query->header);

  // Question
  query->question.qname = "";
  query->question.qnameParts.clear(); 
  int qnameSize = getDomainName(query->question.qname,
                                query->question.qnameParts, dCur, dEnd,
                                false);
  dCur += qnameSize;

  query->question.qtype = ntohs(*(uint16_t *)(dCur));
  query->question.qclass = ntohs(*(uint16_t *)(dCur + 2));

  dCur += 4;

  // Checking for DNSSEC additional section
  query->isDNSSEC = false;
  if(query->header.arcount) {
    uint8_t name = *dCur;
    uint16_t type = ntohs(*(uint16_t *)(dCur + 1));
    uint16_t udpSize = ntohs(*(uint16_t *)(dCur + 3));
    uint8_t extRCODE = *(dCur + 5);
    uint8_t edns0Ver = *(dCur + 6);
    uint16_t z = ntohs(*(uint16_t *)(dCur + 7));
    uint16_t dataSize = ntohs(*(uint16_t *)(dCur + 9));

    // Hush warning for unused variables.
    UNUSED(name);
    UNUSED(udpSize);
    UNUSED(extRCODE);
    UNUSED(edns0Ver);
    UNUSED(dataSize);

    if(type == 0x0029 && z == 0x8000) {
      query->isDNSSEC = true;
    }
  }

  return 0;
}

bool dnsIsValidType(uint16_t value) {
  return validTypes[value];
}

bool dnsIsValidClass(uint16_t value) {
  return validClasses[value];
}

bool dnsIsValidTLD(const char *name) {
  return validTLDs.find(name) != validTLDs.end();
}

