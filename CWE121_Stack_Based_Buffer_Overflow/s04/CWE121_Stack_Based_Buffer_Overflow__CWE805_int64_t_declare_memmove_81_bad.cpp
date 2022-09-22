/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_bad.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-81_bad.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sinks: memmove
 *    BadSink : Copy int64_t array to data using memmove
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */
#ifndef OMITBAD

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81
{

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_bad::action(int64_t * data) const
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memmove(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

}
#endif /* OMITBAD */
