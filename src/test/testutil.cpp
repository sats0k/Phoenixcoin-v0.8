#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <string>

#include <boost/test/unit_test.hpp>
#include <filesystem>
#include <boost/preprocessor/stringize.hpp>

#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_reader_template.h"
#include "script.h"
#include "util.h"

using namespace std;
using namespace json_spirit;

static bool IsDigit(char ch)
{
    return std::isdigit(static_cast<unsigned char>(ch)) != 0;
}

CScript
ParseScript(string s)
{
    CScript result;

    static map<string, opcodetype> mapOpNames;

    if (mapOpNames.size() == 0)
    {
        for (int op = OP_NOP; op <= OP_NOP10; op++)
        {
            const char* name = GetOpName((opcodetype)op);
            if (strcmp(name, "OP_UNKNOWN") == 0)
                continue;
            string strName(name);
            mapOpNames[strName] = (opcodetype)op;
            // Convenience: OP_ADD and just ADD are both recognized:
            size_t nPos = strName.find("OP_");
            if (nPos != std::string::npos)
                strName.erase(nPos, 3);
            mapOpNames[strName] = (opcodetype)op;
        }
    }

    vector<string> words;
    {
        string strToken;
        for (char ch : s) {
            if (ch == ' ' || ch == '\t' || ch == '\n') {
                if (!strToken.empty()) {
                    words.push_back(strToken);
                    strToken.clear();
                }
            } else {
                strToken += ch;
            }
        }
        if (!strToken.empty())
            words.push_back(strToken);
    }

    for (string w : words)
    {
        if (std::all_of(w.begin(), w.end(), IsDigit) ||
            (w.starts_with("-") && std::all_of(w.begin() + 1, w.end(), IsDigit)))
        {
            // Number
            int64 n = atoi64(w);
            result << n;
        }
        else if (w.starts_with("0x") && IsHex(string(w.begin()+2, w.end())))
        {
            // Raw hex data, inserted NOT pushed onto stack:
            std::vector<unsigned char> raw = ParseHex(string(w.begin()+2, w.end()));
            result.insert(result.end(), raw.begin(), raw.end());
        }
        else if (w.size() >= 2 && w.starts_with("'") && w.ends_with("'"))
        {
            // Single-quoted string, pushed as data. NOTE: this is poor-man's
            // parsing, spaces/tabs/newlines in single-quoted strings won't work.
            std::vector<unsigned char> value(w.begin()+1, w.end()-1);
            result << value;
        }
        else if (mapOpNames.count(w))
        {
            // opcode, e.g. OP_ADD or OP_1:
            result << mapOpNames[w];
        }
        else
        {
            BOOST_ERROR("Parse error: " << s);
            return CScript();
        }
    }

    return result;
}

Array
read_json(const std::string& filename)
{
    namespace fs = std::filesystem;
    fs::path testFile = fs::current_path() / "test" / "data" / filename;

#ifdef TEST_DATA_DIR
    if (!fs::exists(testFile))
    {
        testFile = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
    }
#endif

    ifstream ifs(testFile.string().c_str(), ifstream::in);
    Value v;
    if (!read_stream(ifs, v))
    {
        if (ifs.fail())
            BOOST_ERROR("Cound not find/open " << filename);
        else
            BOOST_ERROR("JSON syntax error in " << filename);
        return Array();
    }
    if (v.type() != array_type)
    {
        BOOST_ERROR(filename << " does not contain a json array");
        return Array();
    }

    return v.get_array();
}