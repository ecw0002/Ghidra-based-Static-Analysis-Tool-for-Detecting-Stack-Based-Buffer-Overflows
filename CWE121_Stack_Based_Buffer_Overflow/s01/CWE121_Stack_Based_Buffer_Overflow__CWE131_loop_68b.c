/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_68b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE131.label.xml
Template File: sources-sink-68b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Allocate memory without using sizeof(int)
 * GoodSource: Allocate memory using sizeof(int)
 * Sink: loop
 *    BadSink : Copy array to data using a loop
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

extern int * CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_68_badData;
extern int * CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_68_goodG2BData;

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITBAD

void CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_68b_badSink()
{
    int * data = CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_68_badData;
    {
        int source[10] = {0};
        size_t i;
        /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
        for (i = 0; i < 10; i++)
        {
            data[i] = source[i];
        }
        printIntLine(data[0]);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_68b_goodG2BSink()
{
    int * data = CWE121_Stack_Based_Buffer_Overflow__CWE131_loop_68_goodG2BData;
    {
        int source[10] = {0};
        size_t i;
        /* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */
        for (i = 0; i < 10; i++)
        {
            data[i] = source[i];
        }
        printIntLine(data[0]);
    }
}

#endif /* OMITGOOD */
