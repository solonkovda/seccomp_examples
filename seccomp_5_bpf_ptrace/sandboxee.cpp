/* A simple application to demonstrate seccomp + ptrace combination.

   This application opens a file, given in argv and output it.
   By design it is only allowed to open .txt files, but a error was made and
   it can access any files and only sandbox can stop it.
*/

#include <iostream>
#include <fstream>
#include <string>

using std::cin;
using std::cout;
using std::endl;

int main(int argc, char **argv) {
    if (argc == 1) {
        cout << "Not enough arguments. Provide path to file" << endl;
        return 1;
    }
    char *filename = argv[1];
    std::ifstream inFile;
    inFile.open(filename);
    std::string line;
    while (std::getline(inFile, line)) {
        cout << line << '\n';
    }
    inFile.close();
}
