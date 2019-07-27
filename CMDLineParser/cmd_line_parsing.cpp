#ifdef __linux__ 
#include <linux/version.h>
#include <unistd.h>
#else
#include <process.h>
#define getpid _getpid
#endif
#include <iostream>
#include <cstdio>
#include "cmd_line_parsing.h"

namespace cmd_line {

  // strange dildo code =(
  // don't read it (care about your brain)
  bool cmd_line_parser::Init(std::string exename, std::string HelpMessagePreffix, int argc, char* argv[])
  {
    bool retval = true;
    _exename = exename;
    maxLengthParam   = 1;
    maxLengthExample = 1;
    _HelpMessagePreffix = HelpMessagePreffix;

    InitParam("-h", "", "", "Print this help", false);

#ifndef NDEBUG
    InitParam("-D", "", "", "For debugging",   false);
#endif

    for(auto &p: _Data){
      if(p.first.length() > maxLengthParam) maxLengthParam = p.first.length();
      if(p.second.helpexample.length() > maxLengthExample) maxLengthExample = p.second.helpexample.length();
    }

    std::string paramName;

    for (int i = 1; i < argc; ++i){
      std::string param = "";

      if (argv[i][0] == '-') {
        paramName = argv[i];
      }
      else {
        param = argv[i];
      }

      if (i == 1 && paramName.empty()) {
        paramName = "--input";
      }

      if (!paramName.empty()) {
        if (_Data.find(paramName) == _Data.end()) {
          std::cout << "ERROR: The parameter " << paramName << " is unrecognized!" << std::endl;
          retval = false;
          continue;
        }
        _Data[paramName].IsExist = true;

        if (!param.empty()) {
          _Data[paramName].paramvalues.insert(param);
        }
      }
    }

    for(auto &p: _Data){
      if(p.second.IsMust && !p.second.IsExist) retval = false;
      if(p.first == "-h" && p.second.IsExist)  retval = false;
    }

#ifndef NDEBUG
    if(GetParam("-D")){
      std::cout << "Press Enter to start program! Pid is: " << getpid() << std::endl << std::flush;
      getchar();
      std::cout << "Program started!" << std::endl << std::flush;
    }else{
      std::cout << "Program started! Pid is: " << getpid() << std::endl << std::flush;
    }
#endif

    return retval;
  }

  template<typename T>
  void cmd_line_parser::InitParam(std::string param, T defaultvalue, std::string format, std::string description, bool mustHave)
  {
    auto ToAdd_find = _Data.find(param);
    _Param ToAdd_;
    _Param& ToAdd = ToAdd_find == _Data.end() ? ToAdd_ : ToAdd_find->second;
    ToAdd.helpmessage = description;
    ToAdd.helpexample = format;
    ToAdd.IsExist     = false;
    ToAdd.defaultvalue = std::string(defaultvalue);
    ToAdd.IsMust      = mustHave;
    ToAdd.Counter     = _Data.size();
    _Data[param]      = ToAdd;
  }

  bool cmd_line_parser::GetParam(std::string paramName) const{
    bool err = false;
    auto param = _Data.find(paramName);
    if (param != _Data.end()){
      err = param->second.IsExist;
    } else {
      err = false;
    }
    return err;
  }

  bool cmd_line_parser::GetParam(std::string paramName, std::string &value, size_t No) const
  {
    bool err = false;
    auto param = _Data.find(paramName);
    if (param != _Data.end()){
      if (param->second.paramvalues.size() < No)
      {
        return false;
      }
      size_t NoCounter = 0;
      for (const std::string& paramblue : param->second.paramvalues)
      {
        if (NoCounter == No)
        {
          value = paramblue;
          break;
        }
        NoCounter++;
      }
      err = param->second.IsExist;
    } else {
      err = false;
    }
    return err;
  }

#define MIN_SEARCHABLE_WORD_LEN 5
  bool cmd_line_parser::GetParams(std::string paramName, ParamValuesType& values, bool toDoHalfs) const
  {
    std::map <std::string, _Param>::const_iterator param = _Data.find(paramName);
    if (param != _Data.end()) {
      values = param->second.paramvalues;
      // halfs of word
      if (toDoHalfs) {
        ParamValuesType tmpValues;
        for (const auto& val : values) {
          uint16_t wordSize = static_cast<uint16_t>(val.size());
          uint16_t firstHalfLen = (wordSize >> 1) + (wordSize & 0x1);
          uint16_t lastHalfLen = wordSize - firstHalfLen;
          if (lastHalfLen < MIN_SEARCHABLE_WORD_LEN) {
            tmpValues.emplace(val);
          }
          else {
            tmpValues.emplace(val.substr(0, firstHalfLen));
            tmpValues.emplace(val.substr(firstHalfLen));
          }
        }
        values = tmpValues;
      }
      return true;
    }
    return false;
  }
  
  bool cmd_line_parser::tryConvertToInt(const std::string& str, int &value) const
  {
    int temp = 0;
    try{
      temp = std::stoi(str);
      value = temp;
      return true;
    }
    catch(std::invalid_argument ex){
    }
    catch(std::out_of_range ex){
    }
    return false;
  }

  bool cmd_line_parser::tryConvertToInt(const std::string& str, uint64_t &value) const
  {
    uint64_t temp = 0;
    try {
      temp = std::stoull(str);
      value = temp;
      return true;
    }
    catch (std::invalid_argument ex) {
    }
    catch (std::out_of_range ex) {
    }
    return false;
  }

  bool cmd_line_parser::GetParam(std::string paramName, int &value, size_t No) const
  {
    bool err = false;
    std::string valstring;
    err = GetParam(paramName, valstring);
    if (err) {
      tryConvertToInt(valstring, value);
    }
    return err;
  }

  bool cmd_line_parser::GetParam(std::string paramName, uint64_t &value, size_t No) const
  {
    bool err = false;
    std::string valstring;
    err = GetParam(paramName, valstring);
    if(err){
      tryConvertToInt(valstring, value);
    }
    return err;
  }

  bool cmd_line_parser::GetParam(std::string paramName, double &value, size_t No) const
  {
    bool err = false;
    double back_val = value;
    std::string valstring;
    err = GetParam(paramName, valstring);
    if(err){
      try{
        value = std::stod(valstring);
      }
      catch(std::invalid_argument ex){
        value = back_val;
      }
      catch(std::out_of_range ex){
        value = back_val;
      }
    }
    return err;
  }

  #define xstr(s) str(s)
  #define str(s)  #s

  void cmd_line_parser::PrintBuildInfo() const
  {
    std::string _gitMessage;
    _gitMessage += _exename;
    //_gitMessage += " Git:";
    //_gitMessage += "  hash big:      " xstr(GIT_HASH_BIG) "\n";
    //_gitMessage += "  hash small:    " xstr(GIT_HASH_SMALL) "\n";
    //_gitMessage += "  date git:      " xstr(GIT_DATA) "\n";
    _gitMessage += "\n";

#ifdef LINUX_VERSION_CODE
    _gitMessage += "Build on Linux:\n";
    union KernelVersion {
      struct {
        uint8_t v0;
        uint8_t v1;
        uint8_t v2;
      };
      uint32_t v;
    };
    KernelVersion KV; KV.v = LINUX_VERSION_CODE;
    _gitMessage += "  Kernel version:" + std::to_string(KV.v2) + "." + std::to_string(KV.v1) + "." + std::to_string(KV.v0) + "\n";
#endif
#ifdef __GLIBCPP__
    _gitMessage += "  libstdc++ ver: " + std::to_string(__GLIBCPP__) + "\n";
#endif
#ifdef __GLIBCXX__
    _gitMessage += "  libstdc++ ver: " + std::to_string(__GLIBCXX__) + "\n";
#endif
#ifdef __GNUC__
    _gitMessage += "  gcc version:   " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) + "." + std::to_string(__GNUC_PATCHLEVEL__) + "\n";
#endif

#ifdef _MSC_VER
    _gitMessage += "Build on Windows:\n";
#if _MSC_VER == 1910
    _gitMessage += "  MSVC++ 14.1(Visual Studio 2017)\n";
#endif
#if _MSC_VER == 1911
    _gitMessage += "  MSVC++ 14.1(Visual Studio 2017)\n";
#endif
#if _MSC_VER == 1912
    _gitMessage += "  MSVC++ 14.1(Visual Studio 2017)\n";
#endif
#if _MSC_VER == 1913
    _gitMessage += "  MSVC++ 14.1(Visual Studio 2017)\n";
#endif
#if _MSC_VER == 1900
    _gitMessage += "  MSVC++ 14.0(Visual Studio 2015)\n";
#endif
#if _MSC_VER == 1800
    _gitMessage += "  MSVC++ 12.0(Visual Studio 2013)\n";
#endif
#if _MSC_VER == 1700
    _gitMessage += "  MSVC++ 11.0(Visual Studio 2012)\n";
#endif
#if _MSC_VER == 1600
    _gitMessage += "  MSVC++ 10.0(Visual Studio 2010)\n";
#endif
#endif
    std::cout << _gitMessage;
    std::cout << std::flush;
  }

  void cmd_line_parser::PrintHelpMessage()
  {
    std::string _helpMessage;
    _helpMessage += "\n";
    _helpMessage += _exename + " - (C) 2018-19 www.pcapfilter.dom \n" + _HelpMessagePreffix + "\n";
    for(size_t c = 0; c < _Data.size() * 2; c++){
      for(auto &p: _Data){
        if(c == p.second.Counter){
          std::string first = p.first;
          std::string &helpexample = p.second.helpexample;
          first.resize(maxLengthParam, ' ');
          helpexample.resize(maxLengthExample, ' ');
          _helpMessage += "         " + first + " " + helpexample + " " + p.second.helpmessage + "\n";
        }
      }
    }
    _helpMessage += "\n\n";
    std::cout << _helpMessage;
    std::cout << std::flush;
  }

}
