/* Name : Riyaz Ahamed
   Batch : ECEP 24012A
   Project : Steganography
   Date : 28/08/2024
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encode.h"
#include "decode.h"
#include "types.h"
#include "common.h"

// CMD LINE VALIDATION (DECODING)
Status read_and_validate_decode_args(int argc,char *argv[], EncodeInfo *encInfo)
{
    if(argc != 3 && argc != 4)
    return e_failure;

    if(strstr(argv[2],".bmp") == NULL)
    return e_failure;
    encInfo->src_image_fname = argv[2];
   
    if(argv[3] != NULL)
    {    
        encInfo->secret_fname = argv[3];
        char *temp = strchr(encInfo->secret_fname,'.');
        if(temp != NULL)
        strcpy(encInfo->user_secret_extn,temp);
    }
    else
    encInfo->secret_fname = NULL;

    return e_success;
}

// DECODING PROCESS FUNCTION
Status do_decoding(EncodeInfo *encInfo)
{
    printf("INFO: ## Decoding Procedure Started ##\n");

    // Open src File
    printf("INFO: Opening Source file\n");
    if(open_src_file(encInfo))
    printf("INFO: Done\n");
    else
    return e_failure;

    // Decoding Magic String Info
    printf("INFO: Decoding Magic String Size\n");
    if(decode_magic_string_size(encInfo))
    printf("INFO: Done\n");
    else
    {
        printf("INFO: Failed to Decode magic string size\n");
        return e_failure;
    }

    printf("INFO: Decoding Magic String\n");
    if(decode_magic_string(encInfo))
    printf("INFO: Done\n");
    else
    {
        printf("INFO: Failed to Decode magic string\n");
        return e_failure;
    }
    
    // Comparing Magic String
    char user_magic_string[11];
    get_user_magic_str(user_magic_string);
    if(!strcmp(encInfo->magic_string,user_magic_string))
    printf("INFO: Magic String Validation Success !\n");
    else
    {
        printf("INFO: Incorrect Magic String !\n");
        return e_failure;
    }

    // Decoding Secret File Extn Info
    printf("INFO: Decoding Secret File Extn Size\n");
    if(decode_file_extn_size(encInfo))
    printf("INFO: Done\n");
    else
    {
        printf("INFO: Failed to Decode Secret File Extn size\n");
        return e_failure;
    }

    printf("INFO: Decoding Secret File Extn\n");
    if(decode_secret_file_extn(encInfo))
    printf("INFO: Done\n");
    else
    {
        printf("INFO: Failed to Decode Secret File Extn\n");
        return e_failure;
    }

    //Creating Output File
    if(encInfo->secret_fname != NULL)
    concate_file_name(encInfo);
    else
    {
        printf("INFO: Output File Not Mentioned ! Creating deafault%s as output file\n",encInfo->extn_secret_file);
        create_default_output_file(encInfo);
        printf("INFO: Done\n");
    }
    
    // Open secret File
    printf("INFO: Opening Secret file\n");
    if(open_output_secret_file(encInfo))
    printf("INFO: Done\n");
    else
    return e_failure;

    // Decoding Secret File Info
    printf("INFO: Decoding Secret File Size\n");
    if(decode_secret_file_size(encInfo))
    printf("INFO: Done\n");
    else
    {
        printf("INFO: Failed to Decode Secret File size\n");
        return e_failure;
    }
    printf("INFO: Decoding Secret File Data\n");
    if(decode_secret_file(encInfo))
    printf("INFO: Done\n");
    else
    {
        printf("INFO: Failed to Decode Secret File data\n");
        return e_failure;
    }
    
    return e_success;
}

// SIZE DECODING FUNCTIONS (INT) 
Status decode_magic_string_size(EncodeInfo *encInfo)
{
    fseek(encInfo->fptr_src_image,54,SEEK_SET);
    char buffer[32];
    if(fread(buffer,32,1,encInfo->fptr_src_image) == 1)
    {
        encInfo->size_magic_string = decode_lsb_to_size(buffer);
        return e_success;
    }
    return e_failure;
    
}
Status decode_file_extn_size(EncodeInfo *encInfo)
{
    char buffer[32];
    if(fread(buffer,32,1,encInfo->fptr_src_image) == 1)
    {
        encInfo->size_secret_file_extn = decode_lsb_to_size(buffer);
        return e_success;
    }
    return e_failure;
    
}
Status decode_secret_file_size(EncodeInfo *encInfo)
{
    char buffer[32];
    if(fread(buffer,32,1,encInfo->fptr_src_image) == 1)
    {
        encInfo->size_secret_file= decode_lsb_to_size(buffer);
        return e_success;
    }
    return e_failure;
    
}

//DATA DECODING FUNCTIONS(STRING or TXT) 
Status decode_magic_string(EncodeInfo *encInfo)
{
    if(encInfo->size_magic_string > 10)
    return e_failure;

    char buffer[encInfo->size_magic_string];
    if(!decode_image_to_string(encInfo->size_magic_string,buffer,encInfo->fptr_src_image))
    return e_failure;

    strcpy(encInfo->magic_string,buffer);
    return e_success;

}
Status decode_secret_file_extn(EncodeInfo *encInfo)
{
    if(encInfo->size_secret_file_extn > 10)
    return e_failure;

    char buffer[encInfo->size_secret_file_extn];
    if(!decode_image_to_string(encInfo->size_secret_file_extn,buffer,encInfo->fptr_src_image))
    return e_failure;

    strcpy(encInfo->extn_secret_file,buffer);
    return e_success;
}
Status decode_secret_file(EncodeInfo *encInfo)
{
    if(decode_image_to_file(encInfo->size_secret_file,encInfo))
    return e_success;
    return e_failure;
}

// LSB TO SIZE CONVERSION FUNCTION
uint decode_lsb_to_size(char *data)
{
   uint size = 0;
   for(int index = 0;index < 32;index++)
   {
        if((data[index] & 1) == 1)
        size = (size | (1 << index));
   }
   return size;
}

// LSB TO STRING CONVERSION FUNCTION(STRING)
Status decode_image_to_string(uint size,char *string,FILE *file_ptr)
{
    char buffer[8];
    char ch;

    for(uint str_ind = 0;str_ind < size;str_ind++)
    {
        ch = 0;
        if(fread(buffer,8,1,file_ptr) != 1)
        return e_failure;

        for(int buff_index = 0;buff_index < 8;buff_index++)
        {
            if(buffer[buff_index] & 1 == 1)
            ch = (ch | (1 << buff_index));
        }
        string[str_ind] = ch;
    }
    string[size] = '\0';
    return e_success;
}

// LSB TO STRING CONVERSION FUNCTION(FILE)
Status decode_image_to_file(uint size,EncodeInfo *encInfo)
{
    char buffer[8];
    char ch;
    rewind(encInfo->fptr_secret);
    for(uint file_ind = 0;file_ind < size;file_ind++)
    {
        ch = 0;
        if(fread(buffer,8,1,encInfo->fptr_src_image) != 1)
        return e_failure;

        for(int buff_index = 0;buff_index < 8;buff_index++)
        {
            if(buffer[buff_index] & 1 == 1)
            ch = (ch | (1 << buff_index));
        }
       if(fputc(ch,encInfo->fptr_secret) == EOF)
       return e_failure;
    }
    return e_success;
}

// FUNCTIONS TO STORE MAGIC STRING
void get_user_magic_str(char *user_magic_str)
{
    printf("Enter Magic String (Max len 10) : ");
    scanf(" %20[^\n]",user_magic_str);
    if(strlen(user_magic_str) > 10)
    {
        printf("INFO: Error ! Magic string size is more than 10 !\n");
        exit(1);
    }
}

// CONCATENATE FILE EXTN FUNCTION
void concate_file_name(EncodeInfo *encInfo)
{
    if(strcmp(encInfo->user_secret_extn,encInfo->extn_secret_file))
    {
        char *secret_fname = malloc(strlen(encInfo->secret_fname) + encInfo->size_secret_file_extn + 1);
        strcpy(secret_fname,strcat(encInfo->secret_fname,encInfo->extn_secret_file));
        encInfo->secret_fname = secret_fname;
    }
}

// CREATE DEFAULT OUTPUT FILE FUNCTION
void create_default_output_file(EncodeInfo *encInfo)
{
    char *secret_fname = malloc(strlen("default") + encInfo->size_secret_file_extn + 1);
    strcpy(secret_fname,"default");
    strcat(secret_fname,encInfo->extn_secret_file);
    encInfo->secret_fname = secret_fname;
}