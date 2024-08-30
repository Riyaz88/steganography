/* Name : Riyaz Ahamed
   Batch : ECEP 24012A
   Project : Steganography
   Date : 28/08/2024
*/

#ifndef ENCODE_H
#define ENCODE_H

#include "types.h" // Contains user defined types

// STORE INFORMATION FOR ENCODING AND DECODING OPERATIONS 
typedef struct _EncodeInfo
{
    /* Source Image info */
    char *src_image_fname;
    FILE *fptr_src_image;
    uint image_capacity;
    uint bits_per_pixel;

    /* Secret File Info */
    char *secret_fname;
    FILE *fptr_secret;
    char extn_secret_file[20];
    uint size_secret_file_extn;
    uint size_secret_file;
    
    /* Stego Image Info */
    char *stego_image_fname;
    FILE *fptr_stego_image;

    /* Magic string info*/
    char magic_string[20];
    uint size_magic_string;

    /*User secret file extn (DECODING)*/
    char user_secret_extn[20];

} EncodeInfo;


// CMD LINE VALIDATION (ENCODING)
Status read_and_validate_encode_args(int argc,char *argv[], EncodeInfo *encInfo);
// ENCODING PROCESS FUNCTION
Status do_encoding(EncodeInfo *encInfo);

// SIZE ENCODING FUNCTIONS (INT) 
Status encode_magic_string_size(EncodeInfo *encInfo);
Status encode_secret_file_extn_size(EncodeInfo *encInfo);
Status encode_secret_file_size(EncodeInfo *encInfo);

//DATA ENCODING FUNCTIONS (STRING or TXT) 
Status encode_magic_string(EncodeInfo *encInfo);
Status encode_secret_file_extn(EncodeInfo *encInfo);
Status encode_secret_file_data(EncodeInfo *encInfo);

// SIZE TO LSB CONVERSION FUNCTION
void encode_size_to_lsb(uint data, char *image_buffer);
// STRING VALUES or TXT DATA TO LSB CONVERSION FUNCTION
Status encode_string_to_image(char *data, uint size,EncodeInfo *encInfo);

// HEADER AND FOOTER COPYING FUNCTIONS
Status copy_bmp_header(FILE *fptr_src_image, FILE *fptr_dest_image);
Status copy_remaining_img_data(EncodeInfo *encInfo);

// FUNCTIONS TO STORE INFO INTO STRUCT (DATA or SIZE) 
void store_magic_string_info(EncodeInfo *encoInfo);
void store_secret_extn_info(EncodeInfo *encInfo);
void store_secret_file_size(EncodeInfo *encInfo);

// FUNCTION TO CHECK CAPACITY
Status check_capacity(EncodeInfo *encInfo);
// FUNCTION TO GET IMAGE SIZE
uint get_image_size_for_bmp(FILE *fptr_image);

#endif
