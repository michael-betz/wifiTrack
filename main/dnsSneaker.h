/*
 * dnsSneaker.h
 *
 *  Created on: Apr 14, 2017
 *      Author: michael
 *
 *  Sneak some data through public hot-spots through crafted DNS requests
 */

#ifndef MAIN_DNSSNEAKER_H_
#define MAIN_DNSSNEAKER_H_
#include <stdint.h>

// take data -->
// partition in 16 byte blocks -->
// AES encode -->
// base32 encode -->
// 26 symbols label -->
// send up to 5 labels per request -->
// up to 145 character request for a 80 byte payload

#define DNS_URL_POSTFIX 						"dnsr.uk.to"
#define DNS_TIMEOUT								10000
#define AES_BLOCK_SIZE  						16							//Also the number of payload bytes per request subdomain
#define DIV_CEIL( x, y )						(x/y + (x % y != 0))
#define DNS_REQUEST_BUFFER_SIZE( dataLength )	(DIV_CEIL(dataLength,AES_BLOCK_SIZE)*27+sizeof(DNS_URL_POSTFIX))
#define CODING_TABLE 							"IQJ6WORKEGL5B4YS3NZMPDHVCUA7FX2T"
//#define CODING_TABLE 							"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
#define SECRET_KEY_256							{0xbe,0xa5,0x93,0x8e,0x43,0x4f,0x65,0xef,0x42,0xe7,0x11,0x45,0xc1,0xa0,0xfb,0x48,0xbf,0x8c,0x1a,0xf0,0x9b,0x36,0x88,0x4e,0x6d,0x6c,0x20,0x25,0xb4,0xf5,0xae,0x7c}


// encodes dataBuffer into a DNS query string
// `dnsRequestBuffer` must be a user provided string buffer of size DNS_REQUEST_BUFFER_SIZE()
void dnsEncode( uint8_t *dataBuffer, uint8_t dataLength, uint8_t *dnsRequestBuffer );

// dnsRequestBuffer = zero terminated string of domain to be dns'ed
uint8_t dnsSend( uint8_t *dnsRequestBuffer );

#endif /* MAIN_DNSSNEAKER_H_ */
