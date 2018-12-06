# IDAMagicStrings

An __[IDA](https://www.hex-rays.com) Python plugin__ to extract information from string constants. The current version of the plugin is able to:

 * Display functions to source files relationships (in a tree and in a plain list, a chooser in IDA language).
 * Display guessed function names for functions.
 * Rename functions according to the source code file their belong + address (for example, memory_mgmt_0x401050).
 * Rename functions according to the guessed function name.

## Running the plugin

When the Python script is executed from within IDA it builds a list of ASCII and Unicode strings found by IDA and then applies a series of regular expressions to extract source code filenames, directories and candidate function names. Then, it shows 3 tabs with information:

 * Candidate function names: The function names guessed from the referenced string constants. Some basic and rudimentary false positive detection is implemented and this data is available in the column "FP?" ("False Positive?").
   * If available, it uses [NLTK](https://www.nltk.org/) to detect the appropriate words that can be function name candidates (i.e., nouns, verbs and names).
 * Source code tree: Just a tree widget showing file names and, inside each one, the functions or references to the source file.
 * Source code files: A list (or chooser in the IDA's language) with source code filenames to function addresses and names.

## Screenshots

Here are some basic screenshots of this IDA Python script functionality:

![Guessed function names:](https://user-images.githubusercontent.com/2945834/49219813-b760f080-f3d4-11e8-9190-c948c8f82ea7.png)
![Source code tree:](https://user-images.githubusercontent.com/2945834/49219945-132b7980-f3d5-11e8-887e-5d749f6ef90e.png)
![Renaming some unnamed functions based on its filename:](https://user-images.githubusercontent.com/2945834/49220101-88974a00-f3d5-11e8-86aa-09bfb69379ea.png)

## License

The plugin is licensed under the GNU GPL v3 license.
