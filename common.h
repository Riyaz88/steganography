/* Name : Riyaz Ahamed
   Batch : ECEP 24012A
   Project : Steganography
   Date : 28/08/2024
*/

#ifndef COMMON_H
#define COMMON_H
#include "types.h"

// CHECK OPERTATION TYPE FUNCTION
OperationType check_operation_type(char *argv[]);
// PRINT ERROR FUNCTION
void cmd_line_err(char *argv[]);

// FILE OPEN FUNCTIONS(ENCODING\DECODING)
Status open_src_file(EncodeInfo *encInfo);
Status open_secret_file(EncodeInfo *encInfo);
Status open_output_file(EncodeInfo *encInfo);
Status open_output_secret_file(EncodeInfo *encInfo);

#endif
