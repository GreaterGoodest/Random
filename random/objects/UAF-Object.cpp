#include <iostream>
#include <string>
#include <vector>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

void store(char *data)
{
    char *storage = (char *)malloc(strlen(data));
    memcpy(storage, data, strlen(data));
}

int main()
{
    printf("puts address: %p\n", puts);

    std::string command;
    char data[128] = {0};
    MyLog *logbook = NULL;

    while (1)
    {

        std::cout << "Choose a command:" << std::endl;
        std::cout << "1. Create Log" << std::endl;
        std::cout << "2. Log Message" << std::endl;
        std::cout << "3. Store Data" << std::endl;
        std::cout << "4. Delete Log" << std::endl;
        std::cout << "5. Exit" << std::endl;
        std::cout << "> ";
        std::cin >> command;
        std::cout << command << std::endl;

        
        if (command.compare("1") == 0)
        {
            if (NULL == logbook)
            {
                logbook = new MyLog();
                printf("heap leak: %p\n", logbook);
            }else{
                std::cout << "Logbook already created" << std::endl;
            }
        }
        else if (command.compare("2") == 0)
        {
            if (logbook)
            {
                std::cout << "What do you want to log? (Max 128 chars)" << std::endl;
                std::cout << "data: ";
                std::cin >> data;
                logbook->log(data);
            }else{
                std::cout << "You must create a logbook before logging." << std::endl;
            }
        }
        else if (command.compare("3") == 0)
        {
            std::cout << "data: ";
            std::cin >> data;
            store(data);
        }
        else if (command.compare("4") == 0)
        {
            if (logbook)
            {
                delete logbook;
                //BUG! Need to set logbook to NULL to prevent UAF...
            } else {
                std::cout << "Logbook does not exist" << std::endl;
            }
        }
        else if (command.compare("5") == 0)
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