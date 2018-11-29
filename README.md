# IDAMagicStrings

An IDA Python plugin to extract information from string constants. The current version of the plugin is able to:

 * Display functions to source files relationships (in a tree and in a plain list, a chooser in IDA language).
 * Display guessed function names for functions.
 * Rename functions according to the source code file their belong + address (for example, memory_mgmt_0x401050).
 * Rename functions according to the guessed function name.

## Running the plugin

When the Python script is executed from within IDA it builds a list of ASCII and Unicode strings found by IDA and then applies a series of regular expressions to extract source code filenames, directories and candidate function names. Then, it shows 3 tabs with information:

 * Candidate function names: The function names guessed from the referenced string constants. Some basic and rudimentary false positive detection is implemented and the data available in the column "FP?" ("False Positive?").
 * Source code tree: Just a tree widget showing file names and, inside each one, the functions or references to the source file.
 * Source code files: A list (or chooser in the IDA's language) with source code filenames to function addresses and names.

## Screenshots

Here are some basic screenshots of this IDA Python script functionality:

## License

The plugin is licensed under the GNU GPL v3.
