macro(GIVE_ME_PATH)
if (WIN32)
    set(_path "PATH=")
    string(REPLACE "/" "\\" _path "${_path}")
    string(REPLACE "\\\\" "\\" _path "${_path}")
    string(REPLACE ";;" ";" _path "${_path}")
    string(REPLACE ";;" ";" _path "${_path}")
    if (MSVC14 OR MSVC12 OR MSVC11)
        string(REPLACE "ConfigurationName" "Configuration" _path "${_path}")
    endif ()
    message(STATUS "${_path}")
    set(PATH_DEBUG "${_path}")
endif (WIN32)
endmacro(GIVE_ME_PATH)
