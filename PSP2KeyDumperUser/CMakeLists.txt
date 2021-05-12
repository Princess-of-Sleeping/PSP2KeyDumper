cmake_minimum_required(VERSION 3.0)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(PSP2KeyDumperUser)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(VITA_APP_NAME "PSP2KeyDumper")
set(VITA_TITLEID  "VKEY00001")

set(VITA_VERSION  "01.00")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

# set(VITA_ELF_CREATE_FLAGS "${VITA_ELF_CREATE_FLAGS} -vvv")

enable_language(C ASM)

add_executable(${PROJECT_NAME}
  src/main.c
  src/pup.c
  src/psdif.c
  src/slb2.c
  src/key.c
  src/log.c
  src/fat16/fat16.c
  src/ref00d/ref00d_kprx_auth.c
  src/ref00d/ref00d_utils.c
  src/key_second_loader.c
  src/key_secure_kernel.c
  src/key_kprx_auth.c
  src/key_act.c
  src/key_aimgr.c
  src/key_encdec_w_portability.c
  src/key_gcauthmgr.c
  src/key_update_service.c
  src/key_qaf.c
  src/key_pm.c
)

target_link_libraries(${PROJECT_NAME}
  SceAppMgr_stub
  ScePaf_stub
  SceSysmem_stub
  SceSysmodule_stub
  SceLibKernel_stub
  SceIofilemgr_stub
  SceKernelThreadMgr_stub
  SceSblSsMgr_stub
  taihen_stub
)

set_target_properties(${PROJECT_NAME}
  PROPERTIES LINK_FLAGS "-nostdlib"
)

vita_create_self(eboot.bin ${PROJECT_NAME}
  CONFIG exports.yml
  UNSAFE
  STRIPPED
)

vita_create_vpk(${PROJECT_NAME}.vpk ${VITA_TITLEID} eboot.bin
  VERSION ${VITA_VERSION}
  NAME ${VITA_APP_NAME}
  FILE ${CMAKE_BINARY_DIR}/PSP2KeyDumperKernel/psp2keydumper.skprx psp2keydumper.skprx
)
