Functional Requirements:

The following are the functional requirements for the buffer overflow detection tool.
1. The ODSS script shall run on a Linux x86 64-bit system.
2. The ODSS script shall function as a Ghidra script and use the Ghidra API provided
by a selected Ghidra Version.
3. The ODSS script shall be able to detect buffer overflows in C programs that use the
following libc functions: strcpy(), strncpy(), strlcpy(), strcat(), strncat(), strlcat(),
wcscpy(), wcsncpy(), wcscat(), wcsncat(), memcpy(), memmove(), gets(), and fgets().
4. The ODSS script shall be able to detect buffer overflows in C programs that use the
GCC compiler in its default settings.
5. The ODSS script shall detect buffer overflows in stack-allocated strings.
6. The plugin shall use the NIST Juliet test suite for functional testing.

Design Choices:
This section discusses the design choices for the functional requirements.

Ghidra Use:
Ghidra is a powerful reverse engineering tool that assists in identifying items on the stack and
finding object references (e.g., address locations, function locations, and stack locations)
within the binary file. The Ghidra API allows for finding functions, references, and iterating
through instructions. Ghidra’s function finding API allows for the identification of sinks.
Ghidra’s reference finding API allows for a concise list of how and where various elements
are used in the binary file. Last, Ghidra’s iterating API helps determine where instructions
begin and end. This makes moving up or down through the binary file significantly easier.
This research utilizes Linux-based Ghidra version 9.1-BETA and associated API.

Linux x86 64-bit system:
The script is designed to run on a Linux x86 64-bit operating system. An important
distinction for running the experiment on an x86 64-bit system versus a x86 32-bit system
is the way that parameters are passed. On x86 64-bit systems, the first six parameters are
typically passed in registers. On the x86 32-bit system, parameters are passed on the stack.
Passing the parameters in registers presents a unique, but solvable, challenge to tracking
how values are moved between functions.

Buffer overflow detection used on C programs:
Since the buffer overflow detection method is based on vulnerabilities in libc functions,
it makes sense for the script to only support C programs. Focusing on one programming
language allows the research to have consistency across the different tests and allows for
proper analysis of the functionality of the detection method.

Compilation requirements:
The GCC compiler can optimize the compilation of code in many ways. To maintain
consistency, all test programs are compiled using the default GCC configurations with one
stipulation regarding the -fno-builtin option. This option prevents functions from being
inlined with the code. In this context inlined means that the functions are placed directly in
the code versus making a CALL instruction to the function. There are a few libc functions,
like memmove(), that are inlined when compiled using the default settings. The exact
configurations for GCC can be found in Appendix D. Test cases with multiple files are
statically compiled together.

Buffer overflows in stack-allocated strings:
There are many ways to overflow a buffer. This research focuses on the overflows that
occur from stack-allocated strings. Overflows on the stack are more suited for static analysis
methods. Sizes of the variables that are allocated on the stack are known before run time.
When variables are allocated on the heap, their sizes can grow or shrink as the program
executes. This makes it difficult for static analysis methods to analyze heap-based variables
because the program flow would need to be determined to correctly calculate the space
allocated to the variable.

Functional testing using the Juliet test suite:
The Juliet test suite has a large volume of vulnerable programs that allows for repeatable
testing of the effectiveness of the overflow detection method. The particular set of vulnerabilities
that are relevant to this work comes from the section labeled CWE 121 stack-based
buffer overflow. This set of vulnerabilities exemplifies the type of overflows that this
research aims to detect.

Constraints:
This section describes the capabilities that are not in the scope of this thesis and are not
implemented

Variadic functions:
Variadic functions are functions that take a variable number of parameters. Examples of
this from libc are printf() and scanf(). These functions rely on what is known as a
format specifier to parse the number of parameters it takes. For this research, these types of
functions are excluded from testing. It is not to say that finding a buffer overflow in these
functions is impossible. It would require a different approach to parse the format specifier
first.

Stack manipulation functions:
There are functions that can adjust the stack frame. An example of this is the alloca()
function. The manual page states, “the alloca() function allocates size bytes of space in the
stack frame of the calling function. This temporary space is automatically freed when the
function that called alloca() returns to its caller” [28]. Because of the nature of adjusting
the stack frame, the alloca() function is inlined to the function that calls it. This makes it
difficult to quickly find alloca() when searching through the program. This becomes a task
of finding the behavior of the alloca() function in the code versus determining if a buffer
overflow occurred. In short, functions similar to alloca() are not included in the buffer
overflow tests.

Reversing complex equations:
There are situations where a program uses more than basic arithmetic to calculate values.
It is important to know those values to figure out what inputs are sent to the sinks. To
calculate the values, the equation needs to be discovered. Complex equations would require
a sophisticated state machine to create the equation. This research does not cover the
development of such a state machine. Instead, this thesis is constrained to solving addition
and multiplication equations for input values to the sinks. This research excluded the use
of instructions like SUB or DIV when calculating sizes.

Flow invariant:
In many cases, programs consist of many conditionals that control the execution of the code.
From a static analysis point of view, every possible route through the code would need to
be mapped to determine how a program executes. The main goal of this overflow detection
method is to test the feasibility of tracking a source back to its origin. For the scope of this
research, flow control is not considered. Understanding the control flow of the program can
increase the accuracy of the detection method, however being able to map the control flow
of a program is a separate large topic.

Multiple Register tracking:
There are cases where the source’s location is calculated based on multiple register values.
This is common when indexing into an array. This research implemented single register
tracking when finding sources. This is an area that is discussed in future work.

Limited detection of overflow from concatenation functions:
Since the control flow of the program is not tracked, knowing when a source had values
concatenated to the source is not considered. This thesis investigates overflows caused by
single-use overflows, not the continuous modification of a source that could potentially
cause an overflow. A single-use overflow would be to copy 100 bytes into a 50-byte buffer
once. A continuous overflow would be to copy 1 byte into a 50-byte buffer 100 times.

Limitations:
Identifying the limitations allows for an understanding of what the overflow detection
method cannot do. There are situations that cannot be solved because the problem is
considered undecidable. These limitations are not so much to restrict the implementation
of this detection method, but to instead identify what was not able to be solved.

Validate sources originating from the argument vector:
C programs can take in arguments from the argument vector, argv, when the program is
executed. These values are stored on the stack before the main function’s stack frame. Since
this is done at run time, static analysis would be unable to determine the size or the number
of parameters passed.

False positives in dead code:
If a buffer overflow exists in dead code (i.e., code that is never executed), then it is debatable
whether it is a vulnerability if the buffer overflow cannot occur. Since determining if code
is dead code is an undecidable problem, our overflow detection method is not able to
identify if the overflow is in dead code.

Difficulty in detecting overflows in obfuscated code:
The whole purpose of obfuscating code is to make it difficult for others to determine the
program’s intended behavior. As such, code obfuscation can interfere with the normal
process of iterating through instructions. Our detection method is designed to analyze
binaries created by a GCC compiler. When the assembly code is not generated by the
compiler, the detection method is not always able to detect when an overflow can occur.
This involves the use of inline assembly code that disrupts the compiler’s normal code
generation.

Delineating the different data types inside structures:
When variables of the C data type struct are allocated on the stack, the compiler ensures
that there is enough room to hold the data structures. In cases where a struct is declared but
uninitialized, the compiler would create a section of the stack that is reserved for that struct.
The starting locations of each of the data types inside the struct are unknown, until they are
referenced. The Ghidra experiments described in Appendix E show that the location of an
uninitialized struct’s data types may not be able to be determined if there are not enough
clues in the code.
