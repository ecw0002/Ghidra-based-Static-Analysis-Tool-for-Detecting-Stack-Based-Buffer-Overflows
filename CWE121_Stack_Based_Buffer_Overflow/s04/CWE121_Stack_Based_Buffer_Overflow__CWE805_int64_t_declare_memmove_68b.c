/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_68b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-68b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Set data pointer to the bad buffer
 * GoodSource: Set data pointer to the good buffer
 * Sink: memmove
 *    BadSink : Copy int64_t array to data using memmove
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

extern int64_t * CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_68_badData;
extern int64_t * CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_68_goodG2BData;

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_68b_badSink()
{
    int64_t * data = CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_68_badData;
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memmove(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_68b_goodG2BSink()
{
    int64_t * data = CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_68_goodG2BData;
    {
        int64_t source[100] = {0}; /* fill with 0's */
        /* POTENTIAL FLAW: Possible buffer overflow if data < 100 */
        memmove(data, source, 100*sizeof(int64_t));
        printLongLongLine(data[0]);
    }
}

#endif /* OMITGOOD */
