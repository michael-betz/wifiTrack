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
#define SECRET_KEY_256							{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,}
#define CODING_TABLE							"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


// encodes dataBuffer into a DNS query string
// `dnsRequestBuffer` must be a user provided string buffer of size DNS_REQUEST_BUFFER_SIZE()
void dnsEncode( uint8_t *dataBuffer, uint8_t dataLength, uint8_t *dnsRequestBuffer );

// dnsRequestBuffer = zero terminated string of domain to be dns'ed
uint8_t dnsSend( uint8_t *dnsRequestBuffer );

#endif /* MAIN_DNSSNEAKER_H_ */
