/*
 * Copyright (c) 2018, Department of Information and Communication Engineering.
 * University of Murcia. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author(s):
 *            Jorge Gallego Madrid <jorge.gallego1@um.es>
 *            Jesús Sánchez Gómez  <jesus.sanchez4@um.es>
 */

/**
 * \file
 * \brief Implementation of the schc.h functions.
 *
 * This file implements the SCHC compression/decompression (SCHC C/D)
 * actions as defined in draft-ietf-lpwan-ipv6-static-context-hc-10. The
 * most important functions in this file are schc_compress() and
 * schc_decompress().
 *
 * \note Only a subset of operations of the SCHC C/D are implemented,
 * not all of them.
 *
 * \note The SCHC Fragmentation/Reassembly (SCHC F/R) is not
 * implemented.
 *
 * \note The rule Field Length is not used at all in this
 * implementation, we hardcoded everything in the struct
 * field_description. Solving this requires thinking.
 *
 * To understand better the structure of a schc_packet:
 *
 * \verbatim
 * +--- ... --+------- ... -------+------------------+~~~~~~~
 * |  Rule ID |Compression Residue| packet payload   | padding
 * +--- ... --+------- ... -------+------------------+~~~~~~~
 *                                                    (optional)
 * <----- compressed header ------>
 *
 * Figure 6: from the draft-ietf-lpwan-ipv6-static-context-hc-10
 *
 * \endverbatim
 *
 * \related schc_compress
 */

/**********************************************************************/
/***        Include files                                           ***/
/**********************************************************************/

/**********************************************************************/
/***        Local Include files                                     ***/
/**********************************************************************/

#include "schc.h"
#include "context.h"

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

/**********************************************************************/
/***        Static Variables                                        ***/
/**********************************************************************/

/**********************************************************************/
/***        Static Functions                                        ***/
/**********************************************************************/



static int schc_fragmentate(const uint8_t *schc_packet, size_t schc_packet_len)
{

	/*
	 * If the packet len is equal or less than the max size of a
	 * L2 packet, we send the packet as is, without fragmentation
	 */
	if (schc_packet_len <= MAX_SCHC_PKT_LEN) {


		memcpy(tx_buff, schc_packet, schc_packet_len);
		tx_buff_len = schc_packet_len;


		PRINT_ARRAY(tx_buff, tx_buff_len);

		return 0;

	}

	/*
	 * We start the fragmentation procedure.
	 */



	int nfrag = schc_packet_len / SCHC_FRG_PAY_LEN + (schc_packet_len % SCHC_FRG_PAY_LEN != 0);

	schc_fragment fragments[nfrag];

	memset(fragments, 0, sizeof(fragments));

	size_t bytes_left = schc_packet_len;

	for (int i = 0 ; i < nfrag ; i++) {

		fragments[i].rule_id = 0x80; /* TODO hardcoded, make this generic */
		fragments[i].fcn = nfrag - i -1;

		size_t frg_siz = MIN(sizeof(fragments[i].payload), bytes_left);


		// We send the LoRaWAN packet {


		if (i + 1 < nfrag) {
			// This is not the last SCHC_Fragment
			memcpy(tx_buff, &fragments[i], MIN(sizeof(fragments[i]), sizeof(tx_buff)));
			tx_buff_len = frg_siz + (sizeof(fragments[i]) - sizeof(fragments[i].payload));
		} else {
			// This is the Last Fragment
			// uint16_t checksum (uint16_t *addr, int len);

			uint16_t mic = checksum((uint16_t*)schc_packet, schc_packet_len);

			mic = htons(mic);
			memcpy(&tx_buff[2], &mic, sizeof(mic));
			memcpy(&tx_buff[4], fragments[i].payload, MIN(sizeof(tx_buff), frg_siz));
			tx_buff_len = frg_siz + sizeof(mic) + (sizeof(fragments[i]) - sizeof(fragments[i].payload));

			
		}


		// PRINT("schc_fragmentate, nfrags: ");
		// PRINTLN(nfrag, DEC);
		// PRINTLN("schc_fragmentate, send following Fragment over radio: ");
		// PRINT_ARRAY(tx_buff, tx_buff_len);




		// lorawan_send();


		// } We send the LoRaWAN packet

		bytes_left -= frg_siz;
	}


	return 0;


}


/**
 * \brief Appends the compression residue to the SCHC packet, using the
 * CA action defined in rule_row.
 *
 * \note That this function might not append any bytes to the
 * compression residue. Such thing is possible depending on the rule.
 *
 * @param [in] rule_row The rule row to check the Compression Action
 * (CA) to do to the ipv6_packet target value. Must not be NULL.
 *
 * @param [in] ipv6_packet The original ipv6_packet from wihch we
 * extract the information in case we need to copy some information to
 * the compression residue.
 *
 * @param [in,out] schc_packet The target SCHC compressed packet result of
 * aplying the CA. The function appends as many bytes as it needs
 * depending on the rule_row->CDA. Must be not-null. If the function
 * returns error, the contents of the schc_packet are undefined.
 *
 * function must append bytes to the Compression Residue. Once the
 * function returns, it will point to the next available byte in the
 * schc_packet. The idea is to call this function many times in
 * sequence, every call will append new bytes to the schc_packet, and
 * after the last call, it points where the application payload should
 * be.
 *
 * @return Zero if success, non-zero if error.
 *
 * \note Only implements the following CA:
 * - COMPUTE_LENGTH
 * - COMPUTE_CHECKSUM
 * - NOT_SENT
 *   TODO implement the rest.
 *
 * We just need a quick implementation to start testing with a real
 * scenario, so we don't bother with all the complex compression
 * actions, like the MSB or Map Matching. We need an ad-hoc solution for
 * our tests.
 *
 */
static int do_compression_action(const struct field_description *rule_row,
{
	if (rule_row == NULL || ipv6_packet == NULL) {
		return -1;
	}

	if (rule_row->CDA == COMPUTE_LENGTH || rule_row->CDA == NOT_SENT ||
	    rule_row->CDA == COMPUTE_CHECKSUM) {
		return 0;
	}

	size_t n = 0;
	uint32_t udp_flow_label;
	uint16_t ipv6_payload_length;
	uint16_t udp_dev_port;

	uint16_t udp_app_port;
	uint16_t udp_length;
	uint16_t udp_checksum;

	if (rule_row->CDA == VALUE_SENT) {

		switch (rule_row->fieldid) {
			case IPV6_NEXT_HEADER:
				n = 1;
				return 0;
			case IPV6_HOP_LIMIT:
				n = 1;
				return 0;
			case IPV6_DEV_PREFIX:
				n = 8;
				return 0;
			case IPV6_DEVIID:
				n = 8;
				return 0;
			case IPV6_APP_PREFIX:
				n = 8;
				return 0;
			case IPV6_APPIID:
				n = 8;
				return 0;
			case UDP_DEVPORT:
				n = 2;
				udp_dev_port = htons(ipv6_packet->udp_dev_port);
				return 0;
			case UDP_APPPORT:
				n = 2;
				udp_app_port = htons(ipv6_packet->udp_app_port);
				return 0;
			case UDP_LENGTH:
				n = 2;
				udp_length = htons(ipv6_packet->udp_length);
				return 0;
			case UDP_CHECKSUM:
				n = 2;
				udp_checksum = htons(ipv6_packet->udp_checksum);
				return 0;
				n = 1;
				return 0;
				n = 1;
				return 0;
				n = 1;
				return 0;
				n = 1;
				return 0;
				n = 2;
				return 0;
				return 0;
				n = 1;
				return 0;
				n = 1;
				return 0;
				return 0;
			default:
				break;
		}
	}

	return -1;
}

static int check_matching(struct field_description rule_row, struct field_values ipv6_packet)
{


  if (rule_row.MO == IGNORE) {
    return 1;
  }
 
  if (rule_row.MO == EQUALS) {
    PRINTLN("check_matching entering");

    PRINT("fieldid: ");
    PRINTLN(rule_row.fieldid);

	 uint8_t tv[8] = {0};
    switch (rule_row.fieldid) {

      case IPV6_VERSION:
        return (atoi(rule_row.tv) == ipv6_packet.ipv6_version);
      case IPV6_TRAFFIC_CLASS:
        return (atoi(rule_row.tv) == ipv6_packet.ipv6_traffic_class);
      case IPV6_FLOW_LABEL:
        return (atoi(rule_row.tv) == ipv6_packet.ipv6_flow_label);
      case IPV6_PAYLOAD_LENGTH:
        return (atoi(rule_row.tv) == ipv6_packet.ipv6_payload_length);
      case IPV6_NEXT_HEADER:
        return (atoi(rule_row.tv) == ipv6_packet.ipv6_next_header);
      case IPV6_HOP_LIMIT:
        return (atoi(rule_row.tv) == ipv6_packet.ipv6_hop_limit);
      case IPV6_DEV_PREFIX:
        string_to_bin(tv, rule_row.tv);
        // If the field is not equal, we must return error.
        if (memcmp((void*)&ipv6_packet.ipv6_dev_prefix, (void*)tv, 8) != 0) {
          return 0;
        }
        return 1;
      case IPV6_DEVIID:
        string_to_bin(tv, rule_row.tv);
        // If the field is not equal, we must return error.
        if (memcmp(ipv6_packet.ipv6_dev_iid, tv, 8) != 0) {
          return 0;
        }
        return 1;
      case IPV6_APP_PREFIX:
        string_to_bin(tv, rule_row.tv);
        // If the field is not equal, we must return error.
         
        if (memcmp(ipv6_packet.ipv6_app_prefix, tv, 8) != 0) {
          return 0;
        }
        return 1;
      case IPV6_APPIID:
        string_to_bin(tv, rule_row.tv);
        // If the field is not equal, we must return error.
        if (memcmp(ipv6_packet.ipv6_app_iid, tv, 8) != 0) {
          return 0;
        }
        return 1;
      case UDP_DEVPORT:
        return (atoi(rule_row.tv) == ipv6_packet.udp_dev_port);
      case UDP_APPPORT:
        return (atoi(rule_row.tv) == ipv6_packet.udp_app_port);
      case UDP_LENGTH:
        return (atoi(rule_row.tv) == ipv6_packet.udp_length);
      case UDP_CHECKSUM:
        return (atoi(rule_row.tv) == ipv6_packet.udp_checksum);
        string_to_bin(tv, rule_row.tv);
        
         // If the field is not equal, we must return error.
         
          return 0;
        }
        return 1;
				{
        string_to_bin(tv, rule_row.tv);

        uint8_t tkl = tkl;

        
         // If the field is not equal, we must return error.
         
          return 0;
        }
        return 1;
				}
				{
        string_to_bin(tv, rule_row.tv);

        
        // If the field is not equal, we must return error.
         
          return 0;
        }
        return 1;
				}
      default:
        break;
    }
  }

  PRINTLN("check_matching exit");

  return 0;
}

/**********************************************************************/
/***        Public Functions                                        ***/
/**********************************************************************/


int schc_compress(struct field_values ipv6_packet)
{

	PRINTLN("schc_compress entering");

  //uint8_t schc_packet[SIZE_MTU_IPV6] = {0};
  uint8_t schc_packet[1280] = {0};
  size_t  schc_packet_len = 0;

  /*
   * Pointer to the current location of the schc_packet.
   */

  /*
   * We go through all the rules.
   */

  int nrules = sizeof(rules) / sizeof(rules[0]);
  int field_description_size = sizeof(rules[0])/sizeof(struct field_description); 

  for (int i = 0 ; i < nrules ; i++ ) {

    //struct field_description current_rule[22] = {0};
    struct field_description current_rule[field_description_size];
    memset(current_rule, 0, field_description_size * sizeof(struct field_description));
    memcpy(&current_rule, rules[i], sizeof(current_rule));

    /*
     * number of field_descriptors in the rule.
     */
    int rule_rows = sizeof(current_rule) / sizeof(current_rule[0]);

    int rule_matches = 1; /* Guard Condition for the next loop */


    if (rule_matches == 0) {
			PRINTLN("schc_compress - rule don't matched :(");
			schc_packet_len = 0;
			continue;
		}

    PRINTLN("schc_compress - rule matched!\n");
		/*
		 * At this point, all the MO of the rule returned success, we can
		 * start writing the schc_packet.
		 *
		 * First, we append the Rule ID to the schc_packet
		 */
		schc_packet[schc_packet_len] = i;
		schc_packet_l
    PRINT("schc_packet_len: ");
    PRINTLN(schc_packet_len);

	PRINT("schc_packet: ");
	for (size_t i = 0; i < schc_packet_len; i++){
		PRINT(schc_packet[i], HEX);
		PRINT(" ");
	}
	PRINTLN("");


  /*
    * At this point, Compression Ressidue is already in the packet.
    * We concatenate the app_payload to the packet.
    */


  uint8_t *p = schc_packet + schc_packet_len;


  schc_packet_len += app_payload_len;

	PRINTLN("schc_compression() result: ");
	PRINT_ARRAY(schc_packet, schc_packet_len);


		/*
		 * We have created the SCHC packet, we now go to the Fragmentation
		 * layer and the packet will be sent to the downlink LPWAN tech by
		 * the schc_fragmentate() function as a whole SCHC packet, or as a 
		 * series of fragments.
		 *
		 * If schc_fragmentate succeeds, we return succeed. If it fails,
		 * we return fail.
		 */
	return schc_fragmentate(schc_packet, schc_packet_len);

  }

	/*
	 * No Rule in the context matched the ipv6_packet.
	 */
	return -1;
}

/**********************************************************************/
/***        main() setup() loop()                                   ***/
/**********************************************************************/

/**********************************************************************/
/***        END OF FILE                                             ***/
/**********************************************************************/

/*
 * Deprecated or testing functions start here.
 */

