/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_54c.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__placement_new.label.xml
Template File: sources-sinks-54c.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * BadSource:  Initialize data to a small buffer
 * GoodSource: Initialize data to a buffer large enough to hold a TwoIntsClass
 * Sinks:
 *    GoodSink: Allocate a new class using placement new and a buffer that is large enough to hold the class
 *    BadSink : Allocate a new class using placement new and a buffer that is too small
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

namespace CWE121_Stack_Based_Buffer_Overflow__placement_new_declare_54
{

#ifndef OMITBAD

/* bad function declaration */
void badSink_d(char * data);

void badSink_c(char * data)
{
    badSink_d(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink_d(char * data);

void goodG2BSink_c(char * data)
{
    goodG2BSink_d(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink_d(char * data);

void goodB2GSink_c(char * data)
{
    goodB2GSink_d(data);
}

#endif /* OMITGOOD */

} /* close namespace */
