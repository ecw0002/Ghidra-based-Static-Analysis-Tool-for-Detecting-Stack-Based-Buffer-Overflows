/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE135_81_goodG2B.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-81_goodG2B.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Void pointer to a wchar_t array
 * GoodSource: Void pointer to a char array
 * Sinks:
 *    GoodSink: Allocate memory using wcslen() and copy data
 *    BadSink : Allocate memory using strlen() and copy data
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITGOOD

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE135_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE135_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE135_81_goodG2B::action(void * data) const
{
    {
        /* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * 1);
        (void)strcpy((char *)dest, (char *)data);
        printLine((char *)dest);
    }
}

}
#endif /* OMITGOOD */
