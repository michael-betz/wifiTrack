/*
 * dnsSneaker.c
 *
 *  Created on: Apr 14, 2017
 *      Author: michael
 */
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include <string.h>
#include "hwcrypto/aes.h"

#include "lwip/inet.h"
#include "lwip/ip4_addr.h"
#include "lwip/dns.h"

#include "dnsSneaker.h"

static const char* TAG = "dnsSneaker.c";

xSemaphoreHandle dnsCallbackSema = NULL;
ip_addr_t g_dnsResponse;

/**
 * This convert a 5 bits value into a base32 character.
 * Only the 5 least significant bits are used.
 */
uint8_t encode_char(uint8_t c){
	static uint8_t base32[] = CODING_TABLE;
	return base32[c & 0x1F];  // 0001 1111
}

// encodes 5 bits to 1 byte symbol. Returns pointer to next free element in symbolOutBuffer
uint8_t *base32Encode( uint8_t *plainBuffer, uint32_t len, uint8_t *symbolOutBuffer ){
	uint8_t tmp;
	uint16_t remainder = 0;
	uint8_t remainderCnt = 0;
	uint32_t symbolCount = 0;
	// tempWord holds 64 plain bits --> encodes to 12 whole symbols, remainder 4 bits
	while( 1 ){
		if( remainderCnt >= 5 ){		// Try to consume 5 bits from the remainder
			ESP_LOGI(TAG,"encode_char( %02x)",remainder);
			*symbolOutBuffer++ = encode_char( remainder );
			symbolCount++;
			remainderCnt -= 5;
			remainder >>= 5;
		} else {						// Otherwise extend the remainder with 8 fresh bits
			if( len > 0 ){
				tmp = *plainBuffer++;
				ESP_LOGI(TAG,"Fetched: %02x",tmp);
				remainder |= tmp << remainderCnt;
				remainderCnt += 8;
				len--;
			} else {					// If all plaintext has been encoded, send out the remainder and exit
				if( remainderCnt > 0 ){
					*symbolOutBuffer++ = encode_char( remainder );
					symbolCount++;
				}
				break;
			}
		}
	}
	return symbolOutBuffer;
}

// Print a pretty hex-dump on the debug out
void hexDump( uint8_t *buffer, uint16_t nBytes ){
    for( uint16_t i=0; i<nBytes; i++ ){
        if( (nBytes>16) && ((i%16)==0) ){
        	printf("\n    %04x: ",i);
        }
        printf("%02x ",*buffer++);
    }
    printf("\n");
}

// AES encrypt a 16 byte block in place (not implemented yet)
void encryptBlock( uint8_t *byteBlock ){
	ESP_LOGI(TAG,"Encrypting: ");
	hexDump( byteBlock, 16 );
}

// encodes dataBuffer into a DNS query string
// `dnsRequestBuffer` must be a user provided string buffer of size DNS_REQUEST_BUFFER_SIZE()
void dnsEncode( uint8_t *dataBuffer, uint8_t dataLength, uint8_t *dnsRequestBuffer ){
	ESP_LOGI(TAG, "dnsEncode() %d bytes:", dataLength);
	hexDump( dataBuffer, dataLength );
	uint8_t encryptionBuffer[ AES_BLOCK_SIZE ];
	uint8_t *strPtr = dnsRequestBuffer;

	//-----------------------------------------------------------------
	// Iterate through buffer in 16 byte chuncks and AES encrypt them
	//-----------------------------------------------------------------
	uint8_t chunkNumber = 0;
	uint8_t tempDataLength = dataLength;
	while( tempDataLength > 0 ){
		for( uint8_t i=0; i<AES_BLOCK_SIZE; i++ ){
			if( tempDataLength > 0 ){
				encryptionBuffer[ i ] = *dataBuffer++;
				tempDataLength--;
			} else {
				encryptionBuffer[ i ] = 0;	//Pad with zeros
			}
		}
		encryptBlock( encryptionBuffer );
		// We need to encode 16 byte but base32_encode operates on 5 byte blocks
		// encoding 16 bytes should result in 26 symbols
		strPtr = base32Encode( encryptionBuffer, AES_BLOCK_SIZE, strPtr );
		*strPtr++ = '.';
		chunkNumber++;
	}
	strcpy( (char*)strPtr, DNS_URL_POSTFIX );
	ESP_LOGI( TAG,"dnsEncode(): %s", dnsRequestBuffer );
}

void dnsCallback(const char *name, const ip_addr_t *ipaddr, void *callback_arg){
	memcpy( &g_dnsResponse, ipaddr, sizeof(ip_addr_t) );
	xSemaphoreGive( dnsCallbackSema );
}

// dnsRequestBuffer = zero terminated string of domain to be dns'ed
void dnsSend( uint8_t *dnsRequestBuffer ){
	if (dnsCallbackSema == NULL){
		vSemaphoreCreateBinary( dnsCallbackSema );
	}
	xSemaphoreTake( dnsCallbackSema, 0 );		// Make sure smea is not available already (must be given by dnsCallback)
	dns_init();
	ip_addr_t responseIp;
	dns_gethostbyname( (char*)dnsRequestBuffer, &responseIp, dnsCallback, NULL);
	if( xSemaphoreTake( dnsCallbackSema, DNS_TIMEOUT/portTICK_PERIOD_MS ) ){
		ESP_LOGI( TAG, "DNS done !!!. Response = %s", ip4addr_ntoa(&g_dnsResponse.u_addr.ip4) );
	} else {
		ESP_LOGE( TAG, "DNS timeout");
	}
}
