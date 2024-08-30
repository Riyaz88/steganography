/* Name : Riyaz Ahamed
   Batch : ECEP 24012A
   Project : Steganography
   Date : 28/08/2024
*/

#ifndef TYPES_H
#define TYPES_H

/* User defined types */
typedef unsigned int uint;

/* Status will be used in fn. return type */
typedef enum
{
    e_failure,
    e_success
    
} Status;

typedef enum
{
    e_unsupported,
    e_encode,
    e_decode
    
} OperationType;

#endif


