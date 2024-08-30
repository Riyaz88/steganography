/* Name : Riyaz Ahamed
   Batch : ECEP 24012A
   Project : Steganography
   Date : 28/08/2024
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "encode.h"
#include "types.h"
#include "common.h"

/* FUNCTION DEFINITIONS */

// CMD LINE VALIDATION (ENCODING)
Status read_and_validate_encode_args(int argc,char *argv[], EncodeInfo *encInfo)
{
    // Cmd line arguments count validation
    if(argc != 4 && argc != 5)
    return e_failure;
    
    // Source file extn validation
    if(strcmp(strchr(argv[2],'.'),".bmp"))
    return e_failure;
    encInfo->src_image_fname = argv[2];

    // Secret file extn validation
    if(strstr(argv[3],".") == NULL)
    return e_failure;
    encInfo->secret_fname = argv[3];
    
    // Output file extn validation and Default Output file allocation
    if(argv[4] == NULL)
    {
        printf("INFO: Output File not mentioned. Creating output.bmp as default\n");
        encInfo->stego_image_fname = "output.bmp";
        return e_success;
    }    
    if(strstr(argv[4],".bmp") != NULL)
    {
        encInfo->stego_image_fname = argv[4];
        return e_success;
    }
    else
    return e_failure;
}

// ENCODING PROCESS FUNCTION
Status do_encoding(EncodeInfo *encInfo)
{
    printf("INFO: ## Encoding Procedure Started ##\n");

    // Opening files
    printf("INFO: Opening required files\n");
    if(open_src_file(encInfo) && open_secret_file(encInfo) && open_output_file(encInfo))
    {
        // Storing size,data of secret file extn and secret file.
        store_secret_extn_info(encInfo);
        store_secret_file_size(encInfo);
        printf("INFO: Done\nINFO: ## Encoding procedure started ##\n");
    }
    else
    return e_failure;

    // Validate Secret file is Empty or Not
    if(fgetc(encInfo->fptr_secret) == EOF)
    {
        printf("INFO: %s File is Empty\n",encInfo->secret_fname);
        exit(1);
    }
    rewind(encInfo->fptr_secret);
        
    // Check capacity
    printf("INFO: Checking for %s to handle %s size\n",encInfo->src_image_fname,encInfo->secret_fname);
    if(check_capacity(encInfo))
    printf("INFO: Capacity check Passed !\n");
    else
    {
        printf("INFO: Failure. %s unable to handle %s file size\n",encInfo->src_image_fname,encInfo->secret_fname);
        return e_failure;
    }
    
    // Read and store Magic string
    store_magic_string_info(encInfo);

    // Copy header (54 bytes)
    printf("INFO: Copying Header\n");
    if(copy_bmp_header(encInfo->fptr_src_image,encInfo->fptr_stego_image))
    printf("INFO: Done.\n");
    else
    {
        printf("INFO: Copying Header operation failed\n");
        return e_failure;
    }
    
    // Encoding Magic string size and signature
    printf("INFO: Encoding magic string Signature\n");
    if(!encode_magic_string_size(encInfo))
    {
        printf("INFO: Encoding magic string size operation failed\n");
        return e_failure;
    }
    if(!encode_magic_string(encInfo))
    {
        printf("INFO: Encoding magic string operation failed\n");
        return e_failure;
    }
    printf("INFO: Done\n");

    // Encoding secret file extn size and extn
    printf("INFO: Encoding secret file extn\n");
    if(!encode_secret_file_extn_size(encInfo))
    {
        printf("INFO: Encoding secret file extn size operation failed\n");
        return e_failure;
    }
    if(!encode_secret_file_extn(encInfo))
    {
        printf("INFO: Encoding secret file extn operation failed\n");
        return e_failure;
    }
    printf("INFO: Done\n");

    // Encoding secret file size and data
    printf("INFO: Encoding secret file data\n");
    if(!encode_secret_file_size(encInfo))
    {
        printf("INFO: Encoding secret file size operation failed\n");
        return e_failure;
    }
    if(!encode_secret_file_data(encInfo))
    {
        printf("INFO: Encoding secret file data operation failed\n");
        return e_failure;
    }
    printf("INFO: Done\n");

    // Copy Remaining data
    printf("INFO: Copying Left over Data\n");
    if(copy_remaining_img_data(encInfo))
    {
        printf("INFO: Done\n");
        return e_success;
    }
    else
    {
        printf("INFO: Unable to copy left over data\n");
        return e_failure;
    }             
}

// SIZE ENCODING FUNCTIONS (INT) 
Status encode_magic_string_size(EncodeInfo *encInfo)
{
    char buffer[32];
    if(fread(buffer,32,1,encInfo->fptr_src_image) != 1)
    return e_failure;
    encode_size_to_lsb(encInfo->size_magic_string,buffer);

    if(fwrite(buffer,32,1,encInfo->fptr_stego_image) != 1)
    return e_failure;
    return e_success;
}
Status encode_secret_file_extn_size(EncodeInfo *encInfo)
{
    char buffer[32];
    if(fread(buffer,32,1,encInfo->fptr_src_image) != 1)
    return e_failure;
    encode_size_to_lsb(encInfo->size_secret_file_extn,buffer);

    if(fwrite(buffer,32,1,encInfo->fptr_stego_image) != 1)
    return e_failure;
    return e_success;
}
Status encode_secret_file_size(EncodeInfo *encInfo)
{
    char buffer[32];
    if(fread(buffer,32,1,encInfo->fptr_src_image) != 1)
    return e_failure;
    encode_size_to_lsb(encInfo->size_secret_file,buffer);

    if(fwrite(buffer,32,1,encInfo->fptr_stego_image) != 1)
    return e_failure;
    return e_success;
}

//DATA ENCODING FUNCTIONS (STRING or TXT) 
Status encode_magic_string(EncodeInfo *encInfo)
{
    if(encode_string_to_image(encInfo->magic_string,encInfo->size_magic_string,encInfo))
    return e_success;
    return e_failure;
}
Status encode_secret_file_extn(EncodeInfo *encInfo)
{
    if(encode_string_to_image(encInfo->extn_secret_file,encInfo->size_secret_file_extn,encInfo))
    return e_success;
    return e_failure;
}
Status encode_secret_file_data(EncodeInfo *encInfo)
{
    char buffer[encInfo->size_secret_file];
    rewind(encInfo->fptr_secret);
    if(fread(buffer,encInfo->size_secret_file,1,encInfo->fptr_secret) != 1)
    return e_failure;

    if(encode_string_to_image(buffer,encInfo->size_secret_file,encInfo))
    return e_success;
    return e_failure; 
}

// SIZE TO LSB CONVERSION FUNCTION
void encode_size_to_lsb(uint data, char *image_buffer)
{
    uint bit,byte;
    for(int pos = 0;pos < 32;pos++)
    {
        bit = (data >> pos) & 1;
        byte = image_buffer[pos] & ((unsigned)(1 << 31) - 1 << 1);
        image_buffer[pos] = byte | bit;
    }
}

// STRING VALUES or TXT DATA TO LSB CONVERSION FUNCTION
Status encode_string_to_image(char *data,uint size,EncodeInfo *encInfo)
{
    char buffer[8];
    uint bit,byte;
    for(uint i = 0;i < size;i++)
    {
       if(fread(buffer,8,1,encInfo->fptr_src_image) != 1)
       return e_failure;
       
       for(int j = 0;j < 8;j++)
       {
            bit = (data[i] >> j) & 1;
            byte = buffer[j] & ((1 << 7) - 1 << 1);
            buffer[j] = byte | bit;
       } 
       if(fwrite(buffer,8,1,encInfo->fptr_stego_image) != 1)
       return e_failure;
    }
    return e_success;
}

// FUNCTIONS TO STORE INFO INTO STRUCT (DATA or SIZE) 
void store_magic_string_info(EncodeInfo *encoInfo)
{
    printf("Enter Magic String : ");
    scanf(" %20[^\n]",encoInfo->magic_string);
    if(strlen(encoInfo->magic_string) > 10)
    {
        printf("INFO: Error ! Magic string size is more than 10 !\n");
        exit(1);
    }
    encoInfo->size_magic_string = strlen(encoInfo->magic_string);
}
void store_secret_extn_info(EncodeInfo *encInfo)
{    
    if(strlen(strchr(encInfo->secret_fname,'.')) > 20)
    {
        printf("INFO: Error ! %s file Extn size is more than 20 !\n",encInfo->secret_fname);
        exit(1);
    }
    strcpy(encInfo->extn_secret_file,strchr(encInfo->secret_fname,'.'));
    encInfo->size_secret_file_extn = strlen(encInfo->extn_secret_file); 
}
void store_secret_file_size(EncodeInfo *encInfo)
{
    fseek(encInfo->fptr_secret,0,SEEK_END);
    encInfo->size_secret_file = ftell(encInfo->fptr_secret);
    rewind(encInfo->fptr_secret); 
}

// HEADER AND FOOTER COPYING FUNCTIONS
Status copy_bmp_header(FILE *fptr_src_image, FILE *fptr_dest_image)
{
    rewind(fptr_src_image);
    rewind(fptr_dest_image);
    char buffer[54]; 

    if(fread(&buffer,54,1,fptr_src_image) != 1 || fwrite(&buffer,54,1,fptr_dest_image) != 1)
    return e_failure;
    return e_success;   
}
Status copy_remaining_img_data(EncodeInfo *encInfo)
{
    char buffer[1];
    size_t r_val;
    while(fread(buffer,1,1,encInfo->fptr_src_image) == 1)
    fwrite(buffer,1,1,encInfo->fptr_stego_image);
    
    if(feof(encInfo->fptr_src_image) != 0)
    {
        clearerr(encInfo->fptr_src_image);
        return e_success;
    }
    return e_failure;
}

// FUNCTION TO CHECK CAPACITY
Status check_capacity(EncodeInfo *encInfo)
{
    uint image_capacity = get_image_size_for_bmp(encInfo->fptr_src_image); 
    uint total_size = (encInfo->size_magic_string + encInfo->size_secret_file + encInfo->size_secret_file_extn) * 8;

    if(total_size > image_capacity)
    return e_failure;  
    return e_success; 
}

// FUNCTION TO GET IMAGE SIZE
uint get_image_size_for_bmp(FILE *fptr_image)
{
    uint width, height;
    fseek(fptr_image, 18, SEEK_SET);

    fread(&width, sizeof(int), 1, fptr_image);
    fread(&height, sizeof(int), 1, fptr_image);

    return width * height * 3;
}
