add_executable(panda panda_main.cpp common/panda.cpp)

pybind11_add_module(pandapython panda_python.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(panda
        MOTION::motion
        Boost::program_options
        )

target_link_libraries(pandapython 
        PRIVATE
        MOTION::motion
        Boost::program_options
        )
