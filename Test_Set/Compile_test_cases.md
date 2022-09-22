The Juliet test programs are compiled using GCC 
The programs contain macros to specify pieces of code that are or not part of the compilation
process. These programs are compiled individually, which means each program requires a
main function. These programs are also compiled with the GCC option -fno-builtin. This
prevents the sinks from being inlined to the functions.
The header files std_testcases.h and std_testcases_io.h need to be in the same directory as
the program files. These header files contain variables and macro definitions that are used
in the test programs. The C program io.c is also needed in the compilation process. The
program io.c handles the various print functions that are used in the test case programs.
The examples below use files from the Juliet test suite [3].
Single file compilation example:
gcc nDINCLUDEMAIN -fno-builtin io.c
CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_07.c
-o CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_memcpy_07
In the cases of multiple files, each file will be included in the compilation process.
Multiple file compilation example:
gcc nDINCLUDEMAIN -fno-builtin io.c
CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_54a.c
CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_54b.c
CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_54c.c
CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_54d.c
CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_54e.c
-o CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_54