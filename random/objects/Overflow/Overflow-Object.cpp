#include <iostream>
#include <string>
#include <vector>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_CHUNKS  12

char *chunks[MAX_CHUNKS] = {0};
int currentIndex = 0;

class Logbook
{
public:
    virtual void log(char *message);
};

class MyLog
{
public:
    virtual void log(char *message)
    {
        std::cout << "Got: " << message << std::endl;
    }
};


void store(char *data, int index)
{
    if (NULL == chunks[index])
    {
        chunks[index] = (char *)malloc(strlen(data));
    }else{
        memset(chunks[index], '\0', strlen(chunks[index]));
    }
    memcpy(chunks[index], data, strlen(data)+1);
}

int main()
{

    printf("puts address: %p\n", puts);

    std::string command;
    char data[0x1000] = {0};
    MyLog *logbook = NULL;

    while (1)
    {
        memset(data, 0, sizeof(data));
        std::cout << "Choose a command:" << std::endl;
        std::cout << "1. Create Log" << std::endl;
        std::cout << "2. Log Message" << std::endl;
        std::cout << "3. Store Data" << std::endl;
        std::cout << "4. Edit Data" << std::endl;
        std::cout << "5. Delete Data" << std::endl;
        std::cout << "6. Delete Log" << std::endl;
        std::cout << "7. Exit" << std::endl;
        std::cout << "> ";
        std::cin >> command;
        std::cout << command << std::endl;

        
        if (command.compare("1") == 0) // Create Log
        {
            if (NULL == logbook)
            {
                logbook = new MyLog();
                printf("heap leak: %p\n", logbook);
            }else{
                std::cout << "Logbook already created" << std::endl;
            }
        }
        else if (command.compare("2") == 0) // Log Message (run log function)
        {
            if (logbook)
            {
                std::cout << "What do you want to log? (Max 128 chars)" << std::endl;
                std::cout << "data: ";
                std::cin.width(sizeof(data)+1);
                std::cin >> data;
                logbook->log(data);
            }else{
                std::cout << "You must create a logbook before logging." << std::endl;
            }
        }
        else if (command.compare("3") == 0) // Store Data
        {
            if (currentIndex >= MAX_CHUNKS)
            {
                puts("No more chunks for you!");
                continue;
            }
            std::cout << "data: ";
            std::cin.width(sizeof(data));
            std::cin >> data;
            store(data, currentIndex);
            std::cout << "data stored at index " << currentIndex << std::endl;
            currentIndex++;
        }
        else if (command.compare("4") == 0) // Edit Data
        {
            std::string index_string;
            int index = -1;

            std::cout << "which index do you want to update?" << std::endl;
            std::cin >> index_string;  
            index = std::stoi(index_string);
            
            if (index >= MAX_CHUNKS)
            {
                puts("index out of range!");
                continue; 
            }

            if (!chunks[index])
            {
                puts("chunk not allocated yet!");
                continue;
            }

            printf("previous: %s\n", chunks[index]);

            std::cout << "data: ";
            std::cin.width(sizeof(data));
            std::cin >> data;
            store(data, index);
        }
        else if (command.compare("5") == 0) // Delete Data
        {
            std::string index_string;
            int index = -1;

            if (logbook)
            {
                std::cout << "which index do you want to delete?" << std::endl;
                std::cin >> index_string;  
                index = std::stoi(index_string);
                
                if (index >= MAX_CHUNKS)
                {
                    puts("index out of range!");
                    continue; 
                }

                free(chunks[index]);
                chunks[index] = NULL;
            }
        }
        else if (command.compare("6") == 0) // Delete Logbook
        {
            if (logbook)
            {
                delete logbook;
                logbook = NULL; //Bug fixed from last time! Now impossible to hack.
            } else {
                std::cout << "Logbook does not exist" << std::endl;
            }
        }
        else if (command.compare("7") == 0) // Exit
        {
            return 0;
        }
        else
        {
            std::cout << "Unknown command" << std::endl;
        }
        if (*data){ memset(data, 0, sizeof(*data)); }
    }
}