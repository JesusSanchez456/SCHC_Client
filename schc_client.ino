/**********************************************************************/
/***        Include files                                           ***/
/**********************************************************************/

#include <stdint.h>

/**********************************************************************/
/***        Local Include files                                     ***/
/**********************************************************************/



#include "context.h"
#include "schc.h" 
#include "lorawan.h" 

/**********************************************************************/
/***        Macro Definitions                                       ***/
/**********************************************************************/



// #define DEBUG

#ifdef DEBUG

	#warning "DEBUG MODE ACTIVATED!"

	#define PRINT(...) Serial.print(__VA_ARGS__)
	#define PRINTLN(...) Serial.println(__VA_ARGS__)
	#define PRINT_ARRAY(add, len) \
	do { \
		int i; \
		for (i = 0 ; i < (len) ; i++) { \
			if (i % 10 == 0) \
				Serial.println(); \
			if (i % 50 == 0) \
				Serial.println(); \
			Serial.print((((uint8_t*)(add))[i]), HEX); \
			Serial.print(" "); \
		} \
		Serial.println(); \
	} while(0)

#else /* DEBUG */

	#define PRINT(...)
	#define PRINTLN(...)
	#define PRINT_ARRAY(add, len)

#endif /* DEBUG */





/*
 * Arduino loop() state machine
 */
#define LOOP_SEND_PACKET 1
#define LOOP_IDLE 2



/**********************************************************************/
/***        Type Definitions                                        ***/
/**********************************************************************/

/**********************************************************************/
/***        Forward Declarations                                    ***/
/**********************************************************************/

/**********************************************************************/
/***        Constants                                               ***/
/**********************************************************************/

/**********************************************************************/
/***        Global Variables                                        ***/
/**********************************************************************/


// 1098 Bytes == SCHC RuleID + 1097 Bytes of payload.
char lorem[] = /* UDP payload */ "hola mundo";


/**********************************************************************/
/***        Static Variables                                        ***/
/**********************************************************************/


// SCHC Fragmentation/Reassembly {

static uint8_t fcn_current = 0;
static uint8_t schc_reassemble_buf[SIZE_MTU_IPV6] = {0};
static uint8_t schc_reassemble_offset = {0};

// }



/*
 * We set this variable to 1 if we are reassembling an SCHC packet and
 * keep polling the LoRaWAN server for more downlink packets. If the reassembly
 * finished (either with success or with failure) we reset this variable to 0.
 */
static int ask_next_fragment = 0;

// Research tests counters, only useful when running tests applications.
// Not needed for the operation of the SCHC logic.
// {
static int long_packet_tx_counter          = 0;
static int short_packet_tx_counter         = 0;
static int rx_packet_counter               = 0;
static int mac_tx_error_counter            = 0; // If mac tx returns something different from mac_tx_ok.
static int duplicated_packet_counter       = 0;
static int schc_reassemble_success_counter = 0;
static int schc_reassemble_fail_counter    = 0;
static int rx_len_was_zero_counter         = 0;
static int ipv6_packet_sent_counter        = 0; // Increased Everytime we send the whole "lorem[]" payload.
// }

/*
 * Arduino loop() state machine
 */

static uint32_t generate_uplink_schc_packet = 0; // Last time an uplink packet was generated
static uint32_t generate_uplink_schc_packet_interval = 15000; // Send a packet each n millis.


static int arduino_loop_state = LOOP_SEND_PACKET;

/**********************************************************************/
/***        Static Functions                                        ***/
/**********************************************************************/





/**********************************************************************/
/***        Public Functions                                        ***/
/**********************************************************************/


int freeRam () {
  extern int __heap_start, *__brkval; 
  int v; 
  return (int) &v - (__brkval == 0 ? (int) &__heap_start : (int) __brkval); 
}

/**********************************************************************/
/***        main() setup() loop()                                   ***/
/**********************************************************************/

void setup() {
  Serial.begin(115200);

	// We wait for the Serial UART to be ready.
	// We will exit the loop when the UART reports to be ready.
	while(!Serial)
		 ;

  
uint8_t payload[] = {0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x11, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, // IPv6 header
                        0x27, 0xff, 0xfe, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xf0,
                        0x08, 0xda, 0x05, 0xcb, 0xe1, 0x9a,
                        0xe7, 0xdb, 0x16, 0x33, 0x00, 0x46, 0xb2, 0x98, // UDP Header
                        0x42, 0x02, 0x19, 0xeb, 0x4d, 0x6a, 0xb7, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0xff, // CoAP header
                        0x31, 0x30, 0x30, // Payload
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31}; // 111 B 

	lorawan_setup();
}


void loop() {

	uint32_t current_millis = millis(); // Current timestamp

	/*
	 * Arduino Specific Code
	 *
	 * Manage downlink data.
	 *
	 * {
	 */
	switch (arduino_loop_state) {
		case LOOP_SEND_PACKET:
			{
			//Init pana state machine
			Serial.println("Generating SCHC packet");

		  struct field_values udpIp6_packet;

		  // Ipv6 header fields 
		  udpIp6_packet.ipv6_version = 6;
		  udpIp6_packet.ipv6_traffic_class = 0;
		  udpIp6_packet.ipv6_flow_label = 0;
		  udpIp6_packet.ipv6_payload_length = 0; // Nwk to host
		  udpIp6_packet.ipv6_next_header = 17;
		  udpIp6_packet.ipv6_hop_limit = 64;
		  // Udp header fields
		  //udpIp6_packet.udp_dev_port = 59355; // Nwk to host
		  udpIp6_packet.udp_dev_port = 0xE7DB;
		  //udpIp6_packet.udp_app_port = 5683; // Nwk to host
		  udpIp6_packet.udp_app_port = 0x1633;
		  udpIp6_packet.udp_length = 0; // Nwk to host, length includes header
		  udpIp6_packet.udp_checksum = 0;
		  // Coap header fields
		  udpIp6_packet.coap_version = 1;
			udpIp6_packet.coap_type = 0;
			udpIp6_packet.coap_tkl = 2;
			udpIp6_packet.coap_code = 2;
			udpIp6_packet.coap_message_id[0] = 0;
			udpIp6_packet.coap_message_id[1] = 0;
		  //udpIp6_packet.coap_token = token;
		  uint8_t token[16] = "ab3456789123456";
		  for (size_t i = 0; i < 16; i++)
			 udpIp6_packet.coap_token[i] = token[i];
		  udpIp6_packet.coap_option_delta = 11;
		  udpIp6_packet.coap_option_length = 7;
		  //udpIp6_packet.coap_option_value = value;
		  uint8_t value[16] = "storage";
		  for (size_t i = 0; i < 16; i++)
			 udpIp6_packet.coap_option_value[i] = value[i];
			udpIp6_packet.coap_payload_length = strlen(lorem);
			PRINTLN(udpIp6_packet.coap_payload_length);
			PRINTLN(lorem);
			memcpy(udpIp6_packet.coap_payload, lorem, strlen(lorem));


			/* -----*/
			string_to_bin(udpIp6_packet.ipv6_dev_prefix, "fe80000000000000");
			string_to_bin(udpIp6_packet.ipv6_dev_iid,    "080027fffe000000");
			string_to_bin(udpIp6_packet.ipv6_app_prefix, "fe80000000000000");
			string_to_bin(udpIp6_packet.ipv6_app_iid,    "0a0027fffe656550");



		//  IP addresses
		//  for (int i = 0; i < 8; i++){
		//    udpIp6_packet.ipv6_dev_prefix[i] = 1;
		//  }
		//  for (int i = 8; i < 16; i++){
		//    udpIp6_packet.ipv6_dev_iid[i-8] = 1;
		//  }
		//  for (int i = 0; i < 8; i++){
		//    udpIp6_packet.ipv6_app_prefix[i] = 1;
		//  }
		//  for (int i = 8; i < 16; i++){
		//    udpIp6_packet.ipv6_app_iid[i-8] = 1;
		//  }





		  schc_compress(udpIp6_packet);

			//generar y enviar el paquete

			arduino_loop_state = LOOP_IDLE;

			break;
			}

		case LOOP_IDLE:

			if (current_millis - generate_uplink_schc_packet >= generate_uplink_schc_packet_interval) {
				arduino_loop_state = LOOP_SEND_PACKET;
				generate_uplink_schc_packet = current_millis;
			}

			break;
	}
                        
  //  Serial.print("millis: ");
  //  Serial.print(millis()); //prints time since program started
  //  Serial.print(", micros: ");
  //  Serial.print(micros()); //prints time since program started
  //
  //  Serial.print(", heap: ");
  //  Serial.println(freeMemory());

  // delay(2000);

	// Serial.println(freeRam());


}

/**********************************************************************/
/***        END OF FILE                                             ***/
/**********************************************************************/

/*
 * Deprecated or testing functions start here.
 */

