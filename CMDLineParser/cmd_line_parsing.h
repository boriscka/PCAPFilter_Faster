#ifndef cmd_line_parsing_h
#define cmd_line_parsing_h

#include <string>
#include <map>
#include <set>

namespace cmd_line {
  typedef std::set<std::string> ParamValuesType;

  class cmd_line_parser {

    struct _Param{
      ParamValuesType paramvalues;
      std::string helpmessage;
      std::string helpexample;
      std::string defaultvalue;
      size_t  Counter;
      bool IsMust;
      bool IsExist;
    };

    size_t maxLengthParam;
    size_t maxLengthExample;
    std::string _exename;
    std::string _HelpMessagePreffix;

    std::map <std::string, _Param> _Data;

  public:
    bool Init(std::string exename, std::string HelpMessagePreffix, int argc, char* argv[]);

	template<typename T>
    void InitParam(std::string param, T defaultvalue, std::string format, std::string description, bool mustHave);

    bool GetParam(std::string param) const;
    bool GetParam(std::string param, int         &value, size_t No = 0) const;
    bool GetParam(std::string param, uint64_t    &value, size_t No = 0) const;
    bool GetParam(std::string param, double      &value, size_t No = 0) const;
    bool GetParam(std::string param, std::string &value, size_t No = 0) const;
    bool GetParams(std::string paramName, ParamValuesType& values, bool toDoHalfs = true) const;
    
	bool tryConvertToInt(const std::string& str, int &value) const;
    bool tryConvertToInt(const std::string& str, uint64_t &value) const;

    void PrintBuildInfo() const;
    void PrintHelpMessage();
  };

}


#endif// cmd_line_parsing_h
