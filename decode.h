/* Name : Riyaz Ahamed
   Batch : ECEP 24012A
   Project : Steganography
   Date : 28/08/2024
*/

#ifndef DECODE_H
#define DECODE_H

#include "types.h"

// CMD LINE VALIDATION (DECODING)
Status read_and_validate_decode_args(int argc,char *argv[], EncodeInfo *encInfo);
// DECODING PROCESS FUNCTION
Status do_decoding(EncodeInfo *encInfo);

// SIZE DECODING FUNCTIONS(INT)
Status decode_magic_string_size(EncodeInfo *encInfo);
Status decode_file_extn_size(EncodeInfo *encInfo);
Status decode_secret_file_size(EncodeInfo *encInfo);

//DATA DECODING FUNCTIONS(STRING or TXT)
Status decode_magic_string(EncodeInfo *encInfo);
Status decode_secret_file(EncodeInfo *encInfo);
Status decode_secret_file_extn(EncodeInfo *encInfo);

// LSB TO SIZE CONVERSION FUNCTION
uint decode_lsb_to_size(char *data);
// LSB TO STRING CONVERSION FUNCTION(STRING)
Status decode_image_to_string(uint size,char *string,FILE *file_ptr);
// LSB TO STRING CONVERSION FUNCTION(FILE)
Status decode_image_to_file(uint size,EncodeInfo *encInfo);

// FUNCTIONS TO STORE MAGIC STRING
void get_user_magic_str(char *user_magic_str);
// CONCATENATE FILE EXTN FUNCTION
void concate_file_name(EncodeInfo *encInfo);
// CREATE DEFAULT OUTPUT FILE FUNCTION
void create_default_output_file(EncodeInfo *encInfo);

#endif
