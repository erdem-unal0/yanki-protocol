[English](README.md) · **Türkçe**

# YANKI Protocol

**YANKI**: *Yerel Ağlarda Noktalararası Katmanlı İletişim* (Türkçe) /
*Layered Inter-Node Communication in Local Networks* (İngilizce).

YANKI Protocol, MeshForest kompakt ikili mesh protokolü için bağımsız Arduino
kütüphanesidir. Protokol kodeğini, AES-128-CMAC kimlik doğrulamasını, replay
penceresini, tekrar bastırmayı, yönetilen flooding rölesini ve ağ geçidi ACK
mantığını yeniden kullanılabilir bir ESP8266 kütüphanesi olarak paketler.

Bu depo, MeshForest ayrımının protokole ait yarısıdır (karar D18). Uygulama
deposu bu kütüphaneyi `firmware/lib/yanki-protocol` yolunda sabitlenmiş bir git
alt modülü olarak tüketir.

## Protokol v1 özeti

- **Topoloji:** yönlendirme durumu tutmayan yönetilen flooding. Her düğüm hem
  sensör hem röledir; geçerli her yeni paket bir kez yeniden yayınlanır ve bu,
  tekrar önbelleği, TTL ve rastgele geri çekilme ile sınırlanır.
- **Paket boyutu:** toplam 60 baytlık paket üst sınırı: 8 bayt başlık, en fazla
  48 bayt yük (payload) ve 4 baytlık MIC. Çok baytlı tüm alanlar
  little-endian'dır.
- **Kimlik doğrulama:** başlık + yük üzerinde AES-128-CMAC (RFC 4493), 32 bit
  MIC'e kısaltılır. Her kurulum için tek bir 128 bit ağ PSK'sı kullanılır.
  Yalnızca kimlik doğrulama; v1 yükleri şifrelemez.
- **Replay koruması:** kaynak başına 16 bit mesaj sayaçları, 64 girişlik modüler
  kabul penceresi ve sınırlı tekrar önbellekleri. Replay durumu yalnızca RAM'de
  tutulur.
- **Uyarı teslimi:** ağ geçidi, `(src, msg_id)` belirten kimliği doğrulanmış bir
  ALERT_ACK'i flooding ile yayar. Kaynak, onay alana kadar uyarıyı +3/+8/+20 s
  anlarında yeniden iletir (toplam dört iletim). Raporlar fire-and-forget'tir.
- **Sınırlı davranış:** yeniden deneme sayıları, kuyruklar, röle yuvaları,
  tekrar önbellekleri ve ağ geçidi belleği sabit boyutludur. Paket yolunda
  sınırsız ayırma yoktur.

Tel üzeri biçimin ve anlambilimin belirleyici tanımı
[docs/protocol-spec.md](docs/protocol-spec.md) dosyasındadır. Protokol
kararları [docs/decision-log.md](docs/decision-log.md) dosyasında kayıtlıdır.

## Durum

**Tezgâh prototipi.** Saha testinden geçmemiştir, sertifikalı bir yangın algılama
değildir ve üretime hazır değildir. Radyo birlikte çalışabilirliği, menzil ve
güvenilirlik bu kütüphane derlemesi için doğrulanmamıştır. Protokol tasarımı,
daha önceki bir tel biçiminde tezgâhta ve bir Python referans modeline karşı
denenmiştir; mevcut little-endian kodek ise hâlâ hava üzerinden yeniden
doğrulanmalıdır. Bu sonuçlar saha performansını ortaya koymaz.

## Kurulum

### Arduino kütüphanesi

Bu depoyu Arduino kütüphaneleri dizininize kopyalayın veya klonlayın, ya da
`.zip` kütüphanesi olarak kurun. Kütüphane yalnızca ESP8266 içindir ve
`YankiProtocol.h` başlığını içerir.

### Git alt modülü

Uygulama deposunun içinden:

```sh
git submodule add <repository-url> firmware/lib/yanki-protocol
```

Ardından kütüphaneyi sketch'inize `#include <YankiProtocol.h>` ile dahil edin.

## API kullanımı

```cpp
#include <YankiProtocol.h>

void setup() {
  Serial.begin(115200);

  // Validate the C++ codec and MIC against the reference vectors.
  Proto::goldenVectorsSelfTest(Serial);

  uint8_t payload[5];
  Proto::buildReport(payload, Proto::SF_DHT_PRESENT | Proto::SF_DHT_VALID,
                     2150, 4200);  // 21.50 C, 42.00 %RH

  uint8_t packet[Proto::MAX_PACKET_LEN];
  uint8_t len = 0;
  bool ok = Proto::encode(DEMO_PSK, DEMO_NET_ID, 0x02, 0x0101,
                          Proto::T_REPORT, payload, sizeof(payload),
                          packet, &len);
  if (!ok) return;

  Proto::Packet decoded;
  int8_t result = Proto::decode(packet, len, DEMO_PSK, DEMO_NET_ID, false,
                                &decoded);
  if (result == Proto::R_OK) {
    Serial.printf("type=%u src=%02X msg_id=%04X len=%u\n",
                  decoded.type, decoded.src, decoded.msg_id, decoded.plen);
  }
}
```

`Proto` ad alanını kullanın. Ana giriş noktaları `Proto::encode`,
`Proto::decode`, yük oluşturucular (`buildReport`, `buildAlert`, `buildAck`,
`buildStatus`), `Proto::ReceiveState` ve `Proto::Node`'dur. `Proto::Node` alım
yolunu, röle zamanlamasını, uyarı yeniden denemelerini ve ağ geçidi ACK
davranışını sağlar; sketch'iniz TX kuyruğunu `popTx()` ile boşaltır ve her
paketi iletir.

`YankiConfig.h` içindeki `DEMO_PSK` ve `DEMO_NET_ID` herkese açık demo yer
tutucularıdır. Bunları yeni rastgele bir anahtarla ve kuruluma özgü bir ağ
kimliğiyle değiştirin. Golden vector'lar demo değerlerine bağlıdır, bu yüzden
onları değiştirmek öz test vector'larını geçersiz kılar.

## Python testlerini çalıştırma

Depo kökünden:

```sh
python tools/proto/protocol.py
python tools/proto/simulate.py
```

`protocol.py` kodek, AES-CMAC, replay penceresi ve protokol birim kontrollerini
çalıştırır. `simulate.py` ayrık olaylı flooding/yeniden deneme senaryolarını
çalıştırır. İkisi de geçmelidir (sırasıyla 50 kontrol ve 9 senaryo).

## Sürüm

1.0.0

## Sınırlamalar

- **Şifreleme yok.** v1 yalnızca kimlik doğrulama ve replay koruması sağlar.
  Sensör okumaları gizli değildir. Şifreleme, protokol sürümü artırılarak
  gelecek bir sürümde ele alınacaktır.
- **Anahtar provizyonu ve rotasyonu çözülmemiştir.** Ağ tek bir paylaşılan PSK
  kullanır; hava üzerinden anahtar dağıtımı veya rotasyon mekanizması yoktur.
  Ele geçirilen bir düğüm anahtarı açığa çıkarır ve her düğüm yeniden
  flaşlanana kadar sahteleme yapılabilmesini sağlar.
- **Replay pencereleri yalnızca RAM'de tutulur.** Tazelik koruması en iyi çaba
  temellidir ve yeniden başlatmada sıfırlanır.
- **Karıştırmaya veya hizmet engellemeye karşı dayanıklılık yok.** Protokol,
  kasıtlı bir radyo karıştırıcısına dayanma iddiasında değildir.
- **Saha testinden geçmemiştir.** Menzil, girişim, anten davranışı, güç tüketimi
  ve yangın algılama doğruluğu doğrulanmamıştır.

protocol-spec §16.1'de belirtilen ve demo derlemesinde bilinen eksiklikler demo
ürün yazılımında da uygulanmamıştır: TX öncesi CCA, `PKTLEN` donanım uzunluk
filtresi, rapor jitter'ı, uyarı yeniden deneme jitter'ı, duty cycle bütçesi
zorlaması, ağ geçidinin düğüm başına tazelik tablosu, `msg_id`'nin yeniden
başlatmalar arasında kalıcılığı, kuruluma özgü bir sync word ve PSK
provizyonu/anahtar saklama. Demo derlemesi sabit tempoyu, birebir +3/+8/+20 s
yeniden denemeleri ve depoya işlenmiş bir yer tutucu anahtarı kullanır. Bu
mekanizmalar herhangi bir kurulum iddiasından önce uygulanmalıdır.

Tam belirtim için [docs/protocol-spec.md](docs/protocol-spec.md) dosyasına,
protokol karar kaydı için [docs/decision-log.md](docs/decision-log.md) dosyasına
bakın.

## Lisans

MIT. Bkz. [LICENSE](LICENSE).
