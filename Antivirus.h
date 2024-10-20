#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
DIR *Dir_Read(char * name);
void Recursive_Read(char * name,int mode);
void scan(char * name,int mode);
void inspect(char *name, int mode);
void monitor(char *name, int mode);
void unlock(char **slices, int size);
void slice(char *C);