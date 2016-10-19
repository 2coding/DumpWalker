# DumpWalker
analyze windows dump file, all you need is just put `DumpWalker.hpp` and `DumpWalker.cpp` in your projects

# Requirement
visual c++ 2010 or later

# Usage:
    unstd::DumpWalker walker(L"xxx.dmp", L"symbolSearchPath");
    auto result = walker.analyze();
more example in .\Test\Test.sln`