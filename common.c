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

int main(int argc, char*argv[])
{
    EncodeInfo encInfo;
    
    // Cmdline argument count validation
    if(argc == 1)
    cmd_line_err(argv);
    
    int operation_type = check_operation_type(argv);
    
    //Check type of Operation [ENCODING or DECODING]
    if(operation_type == e_encode)
    {
        //validation for file names
        if(!read_and_validate_encode_args(argc,argv,&encInfo))
         {
            printf("%s: Encoding: %s -e <.bmp_file> <.text_file> [output file]\n",argv[0],argv[0]);
            exit(0);
        }

        // Encoding operation
        if(do_encoding(&encInfo))
        printf("Info: ## Encoding Done Successfully ##\n");
    }
    else if(operation_type == e_decode)
    {
        //validation for file names
        if(!read_and_validate_decode_args(argc,argv,&encInfo)) 
        {
            printf("%s: Decoding: %s -d <.bmp_file> [output file]",argv[0],argv[0]);
            exit(1);
        }

        //Decoding operation
        if(do_decoding(&encInfo))
        printf("Info: ## Decoding Done Successfully ##\n");
    }
    else
    cmd_line_err(argv);
    
    return 0;
}

// CHECK OPERTATION TYPE FUNCTION
OperationType check_operation_type(char *argv[])
{
   if(!strcmp(argv[1],"-e"))
   return e_encode;

   else if(!strcmp(argv[1],"-d"))
   return e_decode;

   else
   return e_unsupported;  
}

// PRINT ERROR FUNCTION
void cmd_line_err(char *argv[])
{ 
    printf("%s: Encoding: %s -e <.bmp_file> <.text_file> [output file]\n",argv[0],argv[0]);
    printf("%s: Decoding: %s -d <.bmp_file> [output file]",argv[0],argv[0]);

    exit(1);
}

// FILE OPEN FUNCTIONS(ENCODING\DECODING)
Status open_src_file(EncodeInfo *encInfo)
{
    // Src Image file
    encInfo->fptr_src_image = fopen(encInfo->src_image_fname, "r");
    // Do Error handling
    if (encInfo->fptr_src_image == NULL)
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->src_image_fname);
    	return e_failure;
    }
    printf("INFO: Opened %s\n",encInfo->src_image_fname);

    return e_success;
}
Status open_secret_file(EncodeInfo *encInfo)
{
    // Secret file
    encInfo->fptr_secret = fopen(encInfo->secret_fname, "r");
    // Do Error handling
    if (encInfo->fptr_secret == NULL)
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->secret_fname);
    	return e_failure;
    }
    printf("INFO: Opened %s\n",encInfo->secret_fname);

    return e_success;
}
Status open_output_secret_file(EncodeInfo *encInfo)
{
    // Secret file
    encInfo->fptr_secret = fopen(encInfo->secret_fname, "w");
    // Do Error handling
    if (encInfo->fptr_secret == NULL)
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->secret_fname);
    	return e_failure;
    }
    printf("INFO: Opened %s\n",encInfo->secret_fname);

    return e_success;
}
Status open_output_file(EncodeInfo *encInfo)
{
    // Stego Image file
    encInfo->fptr_stego_image = fopen(encInfo->stego_image_fname, "w");
    // Do Error handling
    if (encInfo->fptr_stego_image == NULL)
    {
    	perror("fopen");
    	fprintf(stderr, "ERROR: Unable to open file %s\n", encInfo->stego_image_fname); 
    	return e_failure;
    }
    printf("INFO: Opened %s\n",encInfo->stego_image_fname);
    return e_success;
}