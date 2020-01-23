#include "esphome.h"
#include "SPI.h"
#include "LoRa.h"
#include "Crypto.h"
#include "AES.h"
#include "CTR.h"
#include "string.h"
#include "ArduinoJson.h"

using namespace esphome;

#define csPin 18        // LoRa radio chip select
#define resetPin 14    // LoRa radio reset // -1 for not in use
#define dio0Pin 26      // change for your board; must be a hardware interrupt pin
#define freq 918200000 // LoRa used frequency 868 MHz
#define SF 7           // LoRa used spreadingFactor // ranges from 6-12,default 7 see API docs
#define bw 125E3       // LoRa signal bandwidth in Hz, defaults to 125E3
#define sw 0x12        // LoRa SyncWord ranges from 0-0xFF, default 0x12, see LoRa API docs    !!! MUST be equal on Lora sensor nodes and gateway

#define MAX_PLAINTEXT_SIZE 134
#define MAX_CIPHERTEXT_SIZE 134

byte key[16] = {0x01, 0x02, 0x0b, 0x5b, 0xc6, 0x6e, 0xa5, 0xa3, 0xfa, 0x1a, 0xf7, 0xf3, 0x8d, 0xc3, 0x7a, 0xbc}; // The very secret key !!! MUST be equal on Lora sensor nodes and gateway
byte iv[16] = {0xa7, 0x8a, 0x23, 0x2d, 0xed, 0x1c, 0x77, 0xd8, 0xfd, 0xab, 0x8b, 0x13, 0xc4, 0x8d, 0xb1, 0xf3}; //!!! MUST be equal on Lora sensor nodes and gateway
byte ciphertext[MAX_PLAINTEXT_SIZE] = {0};
byte plaintext[MAX_CIPHERTEXT_SIZE] = {0};
byte old_ciphertext[MAX_PLAINTEXT_SIZE] = {0};
String receive_buf = "";
String rssi = "";
String msg_Numerator = "";
String msg_Mailbox = "";
long Z_VBat = 0;   // 4066345
long Z_ID = 0;       // 12345678
long Z_Stand = 0; // 1130810033
int Z_Pow = 0;      // 1350
int Z_Elaps = 0;  // 32
long Z_msg = 0;     // 32452
int Z_RSSI = 0;    // -123
long B_VBat = 0; // 4066345
bool B_Post = 0; // 1
long B_msg = 0;   // 32452
int B_RSSI = 0;  // -123

CTR<AES128> ctr;

/*--------------------------------------------------------------------------------
                            LoRa Data Recieved
--------------------------------------------------------------------------------*/
void onReceive(int packetSize)
{
  // received a packet
  //ESP_LOGD("custom", "Received packet '");

  // read packet
  LoRa.readBytes(ciphertext, MAX_CIPHERTEXT_SIZE);
  //ESP_LOGD("custom", "%s", ciphertext);

  // print RSSI of packet
  rssi = "";
  rssi = String(LoRa.packetRssi());
  //ESP_LOGD("custom", "' with RSSI %s", rssi);
}

/*--------------------------------------------------------------------------------
                                  Decode message
--------------------------------------------------------------------------------*/
void decode_msg()
{
  ctr.clear();
  ctr.setKey(key, ctr.keySize());
  ctr.setIV(iv, ctr.ivSize());

  memset(plaintext, 0xBA, sizeof(plaintext)); // reset plaintext variable before next decryption

  ctr.decrypt(plaintext, ciphertext, sizeof(ciphertext)); // decrypt new message

  receive_buf = (char*)plaintext;
  
  //ESP_LOGD("custom", (char*)ciphertext);
  //ESP_LOGD("custom", (char*)plaintext);
  //ESP_LOGD("custom", receive_buf.c_str());
}

/*--------------------------------------------------------------------------------
                           Json String parsing
--------------------------------------------------------------------------------*/
// {"Sensor":"Numerator","VBat":4066345,"ID":12345678,"Stand":1130810033,"Pow":1350,"Elaps":32,"msg":32452,"RSSI":-123}
// {\"Sensor\":\"Numerator\",\"VBat\":4066345,\"ID\":12345678,\"Stand\":1130810033,\"Pow\":1350,\"Elaps\":32,\"msg\":32452,\"RSSI\":-123}
void json_data_pars(String json)
{
  const size_t capacity = JSON_OBJECT_SIZE(8) + 60;
  DynamicJsonBuffer  jsonBuffer(capacity);

  JsonObject& doc = jsonBuffer.parseObject(json);

  String Sens = doc["Sensor"]; // "Numerator"
  
  if (Sens == "Numerator")
  {
    //msg_Numerator = json;
  //ESP_LOGD("custom", "%s", msg_Numerator);
    
    Z_VBat = doc["VBat"];   // 4066345
    Z_ID = doc["ID"];       // 12345678
    Z_Stand = doc["Stand"]; // 1130810033
    Z_Pow = doc["Pow"];      // 1350
    Z_Elaps = doc["Elaps"];  // 32
    Z_msg = doc["msg"];     // 32452
    Z_RSSI = doc["RSSI"];    // -123
  
    /*ESP_LOGD("custom", "%s", Sens.c_str());
    ESP_LOGD("custom", "%li", Z_VBat);
    ESP_LOGD("custom", "%li", Z_ID);
    ESP_LOGD("custom", "%li", Z_Stand);
    ESP_LOGD("custom", "%i", Z_Pow);
    ESP_LOGD("custom", "%i", Z_Elaps);
    ESP_LOGD("custom", "%li", Z_msg);
    ESP_LOGD("custom", "%i", Z_RSSI);*/
  }
  else if (Sens == "MBox")
  {
    //msg_Mailbox = json;
  //ESP_LOGD("custom", "%s", msg_Mailbox);
    
    B_VBat = doc["VBat"]; // 4066345
    B_Post = doc["Post"]; // 1
    B_msg = doc["msg"];   // 32452
    B_RSSI = doc["RSSI"];  // -123
  
  /*ESP_LOGD("custom", "%s", Sens.c_str());
    ESP_LOGD("custom", "%li", B_VBat);
    ESP_LOGD("custom", "%i", B_Post);
    ESP_LOGD("custom", "%li", B_msg);
    ESP_LOGD("custom", "%i", B_RSSI);*/
  }
}


class MyLoRaSensors : public PollingComponent {
 public:
  Sensor *Numerator_sensor_id = new Sensor();
  Sensor *Numerator_sensor_stand = new Sensor();
  Sensor *Numerator_sensor_power = new Sensor();
  Sensor *Numerator_sensor_elaps = new Sensor();
  Sensor *Numerator_sensor_msg = new Sensor();
  Sensor *Numerator_sensor_rssi = new Sensor();
  Sensor *Numerator_sensor_vbat = new Sensor();
  Sensor *mbox_sensor_post = new Sensor();
  Sensor *mbox_sensor_msg = new Sensor();
  Sensor *mbox_sensor_rssi = new Sensor();
  Sensor *mbox_sensor_vbat = new Sensor();
  
  MyLoRaSensors() : PollingComponent(4000) { }
  
  void setup() override {
    // This will be called by App.setup()
  
  LoRa.setPins(csPin, resetPin, dio0Pin); // set CS, reset, IRQ pin

  if (!LoRa.begin(freq)) // initialize radio at "freq" MHz
  {
    ESP_LOGD("custom", "LoRa init failed. Check your connections.");
    while (true); // if failed, do nothing
    //delay(1000);
  }
  //LoRa.setSpreadingFactor(SF);          // set spreadingFactor
  //LoRa.setSignalBandwidth(bw);          // set signal bandwidth
  LoRa.setSyncWord(sw);         // set SyncWord
  ESP_LOGD("custom", "LoRa init succeeded.");
  ESP_LOGD("custom", "Frequency %d Bandwidth %E SF %i SyncWord %x", freq, bw, SF, sw);
  ESP_LOGD("custom", "LoRa Connection ready...");

  // register the receive callback and put the radio into receive mode
  LoRa.onReceive(onReceive);
  LoRa.receive();
  }
  
  void update() override {
    // This will be called by App.loop()
  if (memcmp(old_ciphertext, ciphertext, MAX_CIPHERTEXT_SIZE) != 0) // check if radio recieved new message
  {
    decode_msg();
    receive_buf.replace("\"xxx\"", rssi);
    json_data_pars(receive_buf);
    
    Numerator_sensor_id->publish_state(Z_ID);
    Numerator_sensor_stand->publish_state(Z_Stand*0.0001);
    Numerator_sensor_power->publish_state(Z_Pow);
    Numerator_sensor_elaps->publish_state(Z_Elaps);
    Numerator_sensor_msg->publish_state(Z_msg);
    Numerator_sensor_rssi->publish_state(Z_RSSI);
    Numerator_sensor_vbat->publish_state(Z_VBat*0.000001);
    mbox_sensor_post->publish_state(B_Post);
    mbox_sensor_msg->publish_state(B_msg);
    mbox_sensor_rssi->publish_state(B_RSSI);
    mbox_sensor_vbat->publish_state(B_VBat*0.000001);
    
    for (uint8_t i = 0; i <= MAX_CIPHERTEXT_SIZE; i++)
    {
      old_ciphertext[i] = ciphertext[i];
    }
  }
  }
};