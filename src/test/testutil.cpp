#include <fstream>
#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/preprocessor/stringize.hpp>

#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_reader_template.h"
#include "util.h"

using namespace std;
using namespace json_spirit;

Array
read_json(const std::string& filename)
{
    namespace fs = boost::filesystem;
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