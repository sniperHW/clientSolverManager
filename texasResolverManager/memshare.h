#pragma once

#include <string>
#include <vector>



vector<std::string> string_split(std::string strin, char split);
std::string GetCurrentPath();
int InitMemshare();
void CloseMemshare();
BOOL GetMemAvailable(int& dwMemAvail);