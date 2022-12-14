Ghidra has a well-developed API for performing various tasks on the disassembled information.
The API allows users to write their own scripts to search, edit, or comment on
disassembled information. The scripts can be written in Java or Python to utilize the API.
This appendix describes how to implement a Ghidra script and run the script on a binary
file.
First, the script manager needs to be opened. This can be done by opening a binary file and
clicking on Window, then scrolling down to the script manager icon. The script manager
icon can also be accessed from the top tool bar.

![load_script1](https://user-images.githubusercontent.com/40476527/191776848-1e7596e8-a6d0-4e89-bd46-27e69cdc5010.jpg)

Once opened the script manager’s menu will appear. On the left side of the script manager
is a list of the script folders. These folders are not file locations; instead they are categories
into which the scripts belong. Categorization is based on the first few comments in the
script file. At the top right there are two main buttons of interest. The first is the create
script button. This will allow the user to select a Java or Python file to begin writing a
script. It will also ask for the directory the file should be stored in. This will then open a
text editor, allowing the user to begin writing code. The second button is the directory list.
This allows the user to add directories for Ghidra to use when looking for script files. 

![load_script2](https://user-images.githubusercontent.com/40476527/191776882-0535d9c0-6e3d-48db-978c-5fd65ffe44d0.jpg)

When a script is selected, the file can be viewed and edited by clicking on the basic editor
button. Inside the script, the top few comments determine what Ghidra will display for the
script and how it is categorized. Comments starting with “@category:” determine where
the file is stored in the script folders. For example, if “@category” is “@Bufferoverflow
Detection”, the script will be stored in the “Bufferoverflow Detection” folder.
To run a scripts, the script must be selected. Then, the green run script button will appear,
which if selected, will run the script. 

![load_script3](https://user-images.githubusercontent.com/40476527/191776910-c1e85213-ddf5-480c-af6e-a66e90a53892.jpg)
