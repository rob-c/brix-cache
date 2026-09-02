#include <iostream>
#include <string>

int main(int argc, char **argv)
{
    const std::string value = argc > 1 ? argv[1] : "missing";
    std::cout << "brixtest C++ value=" << value << '\n';
    return value == "ready" ? 0 : 2;
}
