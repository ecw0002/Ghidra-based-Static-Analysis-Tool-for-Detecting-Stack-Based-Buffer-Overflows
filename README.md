**Overflow Detection from Sinks and Sources<h1>**

This repository is part of a thesis to detect stack-based buffer overflows in 
C programs. 

The final product is a single script that can detect buffer overflows using 
Ghidra. The script is intended to run on Ghidra version 9.1-BETA.

To run the script, load the script into Ghidra's script manager. Then open the
binary file that you want to run the analysis on in Ghidra. Then run the script.

The Test_Set folder contains the test cases from the thesis and the results.
