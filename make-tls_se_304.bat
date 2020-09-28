set JC=C:\vaio\jc304
set JDK=C:\jdk1.6.0_03

set _CLASSES=%JC%\lib\api_classic.jar
set  CLASSPATH=%JDK%\lib;%_CLASSES%


%JDK%\bin\javac.exe .\com\ethertrust\tlsse\tls_se.java -classpath %CLASSPATH% 

REM PAUSE

set CLASSPATH=%JDK%\lib;%JC%\lib\tools.jar;%JC%\lib\ant-contrib-1.0b3.jar

REM Converter 2.2.1
REM

set JC_CLASSPATH=%JC%\lib\ant-contrib-1.0b3.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\asm-all-3.1.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\bcel-5.2.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\commons-cli-1.0.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\commons-codec-1.3.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\commons-httpclient-3.0.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\commons-logging-1.1.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\jctasks.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\tools.jar;%JC_CLASSPATH%
set JC_CLASSPATH=%JC%\lib\api_classic.jar;%JC_CLASSPATH%


%JDK%\bin\java -Djc.home=%JC% -classpath %JC_CLASSPATH% com.sun.javacard.converter.Main -classdir . -exportpath %JC%\api_export_files -i -out EXP CAP -applet 0x01:0x02:0x03:0x04:0x05:0x00  com.ethertrust.tlsse.tls_se  com.ethertrust.tlsse  0x01:0x02:0x03:0x04:0x05 1.0

PAUSE


