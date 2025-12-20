build_lib(
  LIBNAME ns3cybermod
  SOURCE_FILES
    model/ns3cybermod.cc
  HEADER_FILES
    ns3cybermod.h  
  LIBRARIES_TO_LINK
    ${libcore}
    ${libnetwork}
    ${libinternet}
    ${libapplications}
    ${libpoint-to-point}
)
