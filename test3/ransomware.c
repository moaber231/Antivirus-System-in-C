#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>


void ransom()
{
    int file_des, file_dess;
    ssize_t bytesRead, bytesWritten;
    char buffer[1000];
    file_dess = open("test3/passwords.txt", O_RDONLY);
    if (file_dess == -1)
    {
        exit(EXIT_FAILURE);
    }
    bytesRead = read(file_dess, buffer, 1000);
    if (bytesRead == -1)
    {
        close(file_dess);
        exit(EXIT_FAILURE);
    }
    close(file_dess); 
    file_des = open("test3/passwords.txt.locked", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (file_des == -1)
    {
        exit(EXIT_FAILURE);
    }
    bytesWritten = write(file_des, buffer, bytesRead); 
    if (bytesWritten != bytesRead)
    {
        close(file_des);
        exit(EXIT_FAILURE);
    }
    close(file_des);
    if (remove("test3/passwords.txt") == -1)
    {
        exit(EXIT_FAILURE);
    }
}
int main()
{
    ransom();
    return 0;
}