@echo OFF

@rem Copyright (c) 2016 nexB Inc. http://www.nexb.com/ - All rights reserved.

@rem ################################
@rem # change these variables to customize this script locally
@rem ################################
@rem # you can define one or more thirdparty dirs, each prefixed with TPP_DIR
set TPP_DIR_BASE=thirdparty/base
set TPP_DIR_DEV=thirdparty/dev
set TPP_DIR_PROD=thirdparty/prod

set DEFAULT_PYTHON=python

@rem # default configurations
set CONF_DEFAULT="etc/conf/dev"
@rem #################################

set DJ_ROOT_DIR=%~dp0

set CFG_CMD_LINE_ARGS= 
@rem Collect/Slurp all command line arguments in a variable
:collectarg
 if ""%1""=="""" (
    goto continue
 )
 call set CFG_CMD_LINE_ARGS=%CFG_CMD_LINE_ARGS% %1
 shift
 goto collectarg

:continue

@rem default to dev configuration when no args are passed
if "%CFG_CMD_LINE_ARGS%"==" " (
    set CFG_CMD_LINE_ARGS="%CONF_DEFAULT%"
    goto configure
)

if "%CFG_CMD_LINE_ARGS%"=="  --init" (
    set CFG_CMD_LINE_ARGS="%CONF_INIT%"
    goto configure
)

if "%PYTHON_EXE%"==" " (
    set PYTHON_EXE="%DEFAULT_PYTHON%"
    goto configure
)


:configure
call "%PYTHON_EXE%" etc/configure.py %CFG_CMD_LINE_ARGS%
goto EOS

:EOS