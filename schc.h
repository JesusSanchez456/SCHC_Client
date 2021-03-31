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

#ifndef SCHC_H
#define SCHC_H

using namespace std;

/**
 * \file
 * 
 * \brief SCHC C/D related functions and struct definition.
 *
 * All the definitions in this file are directly from the
 * draft-ietf-lpwan-ipv6-static-context-hc-10.
 */

/**********************************************************************/
/***        Include files                                           ***/
/**********************************************************************/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <cstring>

/**********************************************************************/
/***        Local Include files                                     ***/
/**********************************************************************/

/**********************************************************************/
/***        Macro Definitions                                       ***/
/**********************************************************************/

#define SIZE_ETHERNET 14
#define SIZE_IPV6 40
#define SIZE_UDP 8
/**
 * This is taken from the LoRaWAN Specification v1.0 Table 17.
 *
 * No matter what, no SCHC packet length should ever be longer than
 * this.
 *
 * Not really a generic solution, since every LPWAN has a different PTU,
 * but for now it servers as an ad-hoc solution for testings.
 *
 * \note See table 17 of the LoRaWAN specification 1R0.pdf for other
 * values.
 */
#define MAX_LORAWAN_PKT_LEN 242

/**
 * The maximum length allowed by schc_fragmentate() to decide if the
 * SCHC packet should be fragmentated or not. All packets longer than
 * this get fragmentated.
 */
#define MAX_SCHC_PKT_LEN 20


// Fragmentation/Reassembly {

/**
 * This is the maximum size of the payload of each SCHC Fragment.
 */
#define SCHC_FRG_PAY_LEN 20 /* TODO this value is set for testing, change to something else */

// } Fragmentation/Reassembly
//
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))


#ifdef __arm__
// should use uinstd.h to define sbrk but Due causes a conflict
extern "C" char* sbrk(int incr);
#else  // __ARM__
extern char *__brkval;
#endif  // __arm__

#define SCHC_FRG_RULEID 0x80

#ifndef UTIL_H
#define UTIL_H

#ifndef htons
#define htons(x) ( ((x)<< 8 & 0xFF00) | \
                   ((x)>> 8 & 0x00FF) )
#endif

#ifndef ntohs
#define ntohs(x) htons(x)
#endif

#ifndef htonl
#define htonl(x) ( ((x)<<24 & 0xFF000000UL) | \
                   ((x)<< 8 & 0x00FF0000UL) | \
                   ((x)>> 8 & 0x0000FF00UL) | \
                   ((x)>>24 & 0x000000FFUL) )
#endif

#ifndef ntohl
#define ntohl(x) htonl(x)
#endif

#endif


/**********************************************************************/
/***        Types Definitions                                       ***/
/**********************************************************************/

// SCHC draft 10, section 6.4
enum MO {
	EQUALS,
	IGNORE,
	MATCH_MAPPING,
	MSB
};

// SCHC draft 10, section 9
enum fieldid {
	IPV6_PAYLOAD_LENGTH,
	IPV6_NEXT_HEADER,
	IPV6_HOP_LIMIT,
	IPV6_DEV_PREFIX,
	IPV6_DEVIID,
	IPV6_APP_PREFIX,
	IPV6_APPIID,

	UDP_DEVPORT,
	UDP_APPPORT,
	UDP_LENGTH,
	UDP_CHECKSUM,

};

// SCHC draft 10, section 6.1
enum direction {
	UPLINK,
	DOWNLINK,
	BI
};

// SCHC draft 10, section 6.5
enum CDA {
	NOT_SENT,
	VALUE_SENT,
	MAPPING_SENT,
	LSB,
	COMPUTE_LENGTH,
	COMPUTE_CHECKSUM,
	DEVIID,
	APPIID
};


struct field_description {
	enum fieldid fieldid;
	size_t field_length; /** Length in bits */
	int field_position;
	enum direction direction;
	char *tv;
	enum MO MO;
	enum CDA CDA;
};

struct field_values {
	uint8_t ipv6_version;
	uint8_t ipv6_traffic_class;
	uint32_t ipv6_flow_label;
	size_t ipv6_payload_length;
	uint8_t ipv6_next_header;
	uint8_t ipv6_hop_limit;
	uint8_t ipv6_dev_prefix[8];
	uint8_t ipv6_dev_iid[8];
	uint8_t ipv6_app_prefix[8];
	uint8_t ipv6_app_iid[8];

	uint16_t udp_dev_port;
	uint16_t udp_app_port;
	size_t udp_length;
	uint16_t udp_checksum;
	
	// TODO: consider what to do with this field
	//uint8_t payload[SIZE_MTU_IPV6]; 

};


typedef struct schc_fragment_s {
	uint8_t rule_id;
	uint8_t fcn;
	uint8_t payload[SCHC_FRG_PAY_LEN];
} schc_fragment;


/**********************************************************************/
/***        Forward Declarations                                    ***/
/**********************************************************************/

int string_to_bin(uint8_t dst[8], const char *src);

/**
 * \brief Applies the SCHC compression procedure as detailed in
 * draft-ietf-lpwan-ipv6-static-context-hc-10 and, in case of success,
 * sends the SCHC Packet or derived SCHC Fragments though the downlink.
 *
 * \note In case of failure or not matching any SCHC Rule, the packet is
 * silently discarded and is not sent through the downlink.
 *
 * @param [in] ipv6_pcaket The original IPv6 packet received from
 * the ipv6 interface. It will be used to apply a SCHC rule and generate
 * a compressed IPv6 Packet.
 *
 * @return 0 if successfull, non-zero if there was an error.
 */
int schc_compress(struct field_values ipv6_packet);

/*
 * TODO comment
 */
int schc_reassemble(uint8_t *lorawan_payload, uint8_t lorawan_payload_len);

/**********************************************************************/
/***        Constants                                               ***/
/**********************************************************************/

/**********************************************************************/
/***        Global Variables                                        ***/
/**********************************************************************/

/**********************************************************************/
/***        AUX Functions                                           ***/
/**********************************************************************/

/**********************************************************************/
/***        MAIN routines                                           ***/
/**********************************************************************/

/**********************************************************************/
/***        END OF FILE                                             ***/
/**********************************************************************/


#endif /* SCHC_H */

// vim:tw=72
