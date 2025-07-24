#include <idc.idc>

static main()
{
    auto fhandle = fopen(ARGV[1], "w+");
    auto result = gen_file(OFILE_IDC, fhandle, 0, BADADDR, 0);
    fclose(fhandle);
    process_config_directive("ABANDON_DATABASE=YES");
    if(result == 1) {
        qexit(0);
    } else {
        qexit(1);
    }
}
