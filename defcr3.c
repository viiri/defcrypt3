/*
 * deFCrypt3 - a decryptor for EXE files protected with "Future Crew FCrypt3",
 *
 * Copyright 2017 Sergei "x0r" Kolzun
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#define MEM_GETB(p) (*(uint8_t *)p)
#define MEM_GETW_LE(p) (((*((uint8_t *)p + 1)) << 8) | (*(uint8_t *)p))
#define MEM_PUTW_LE(p, v) (*((uint8_t *)p) = v & 0xff, *(((uint8_t *)p + 1)) = (v >> 8) & 0xff);

#define e_magic		0x00
#define e_cblp		0x01
#define e_cp		0x02
#define e_crlc		0x03
#define e_cparhdr	0x04
#define e_minalloc	0x05
#define e_maxalloc	0x06
#define e_ss		0x07
#define e_sp		0x08
#define e_csum		0x09
#define e_ip		0x0a
#define e_cs		0x0b
#define e_lfarlc	0x0c

#define f_sp		0x00
#define f_ss		0x01
#define f_ip		0x02
#define f_cs		0x03
#define f_cpar		0x04
#define f_key		0x05
#define f_csum_add	0x06
#define f_csum_sub	0x07

static uint16_t fcr3_checksum(uint8_t *buffer, size_t length);
static uint16_t fcr3_decrypt(uint8_t *buffer, size_t length, uint8_t key);
static void die(const char *fmt, ...);

FILE *fp_in, *fp_out;
uint16_t exe_mz_header[0x10];
uint16_t fcrypt3_header[8];

static uint16_t fcr3_checksum(uint8_t *buffer, size_t length)
{
	size_t i;
	uint16_t checksum = 0;

	for(i = 0; i < length; ++i)
		checksum -= buffer[i];

	return checksum;
}

static uint16_t fcr3_decrypt(uint8_t *buffer, size_t length, uint8_t key)
{
	size_t i, j;
	uint16_t checksum = 0;

	for(i = 0; i < length; i += 0x10)
	{
		for(j = 0; j < 0x10; ++j, ++key)
		{
			checksum += buffer[i + j];
			buffer[i + j] = key - buffer[i + j];
		}

		for(j = 0; j < 8; ++j)
		{
			buffer[i + j + 8] -= buffer[i + j];
			buffer[i + j] ^= buffer[i + j + 8];
		}
	}

	return checksum;
}

static void die(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);

	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");

	va_end(args);

	if(fp_in)
		fclose(fp_in);
	if(fp_out)
		fclose(fp_out);

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	uint8_t *buffer;

	size_t header_length,
		   data_length,
		   decoder_start;

	printf("deFCrypt3 v0.7\n\n");

	if (argc != 3) {
		printf("Usage: %s infile outfile\n", "defcr3");
		return EXIT_SUCCESS;
	}

	if((fp_in = fopen(argv[1], "rb")) == NULL)
		die("Cannot open input file: '%s'!", argv[1]);

	if(fread(exe_mz_header, 1, 0x20, fp_in) != 0x20)
		die("Read error!");

	if(exe_mz_header[e_magic] != 0x5a4d && exe_mz_header[e_magic] != 0x4d5a)
		die("EXE header not found!");

	decoder_start = MEM_GETW_LE(&exe_mz_header[e_cs]) << 4;
	header_length = MEM_GETW_LE(&exe_mz_header[e_cparhdr]) << 4;
	if(fseek(fp_in, header_length + decoder_start, SEEK_SET) == -1)
		die("Read error!");

	if(fread(fcrypt3_header, 1, 0x10, fp_in) != 0x10)
		die("Read error!");

	data_length = MEM_GETW_LE(&fcrypt3_header[f_cpar]) << 4;
	if(!data_length || decoder_start < data_length || data_length < (MEM_GETW_LE(&fcrypt3_header[f_cs]) << 4) + MEM_GETW_LE(&fcrypt3_header[f_ip]))
		die("Bad FCrypt3 header!");

	if(fseek(fp_in, 0, SEEK_SET) == -1)
		die("Read error!");

	decoder_start += header_length;
	if((buffer = malloc(decoder_start)) == NULL)
		die("Not enough memory!");

	if(fread(buffer, 1, decoder_start, fp_in) != decoder_start)
		die("Read error!");

	fclose(fp_in);

	if(fcr3_checksum(buffer + (decoder_start - data_length), data_length) != MEM_GETW_LE(&fcrypt3_header[f_csum_sub]))
		die("File corrupted!");

	if(fcr3_decrypt(buffer + (decoder_start - data_length), data_length, MEM_GETB(&fcrypt3_header[f_key])) != MEM_GETW_LE(&fcrypt3_header[f_csum_add]))
		die("File corrupted!");

	((uint16_t *)(buffer))[e_sp] = fcrypt3_header[f_sp];
	((uint16_t *)(buffer))[e_ss] = fcrypt3_header[f_ss];
	((uint16_t *)(buffer))[e_ip] = fcrypt3_header[f_ip];
	((uint16_t *)(buffer))[e_cs] = fcrypt3_header[f_cs];

	data_length = decoder_start / 0x200;
	header_length = decoder_start % 0x200;
	if(header_length)
		data_length++;

	MEM_PUTW_LE(&((uint16_t *)(buffer))[e_cp], data_length)
	MEM_PUTW_LE(&((uint16_t *)(buffer))[e_cblp], header_length)

	if((fp_out = fopen(argv[2], "wb")) == NULL)
		die("Cannot open input file: '%s'!", argv[2]);

	if(fwrite(buffer, 1, decoder_start, fp_out) != decoder_start)
		die("Write error!");

	printf("OK!\n");

	fclose(fp_out);
	free(buffer);

	return EXIT_SUCCESS;
}
