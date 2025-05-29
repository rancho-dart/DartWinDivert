sc create DartWinDivertService binPath= "C:\Users\admin\source\repos\DartWinDivert\x64\Debug\DartWinDivert.exe"
sc start DartWinDivertService
sc config DartWinDivertService start= auto
sc stop DartWinDivertService

sc description DartWinDivertService "DART WinDivert Service for network packet interception and manipulation."

sc failure DartWinDivertService reset= 86400 actions= restart/60000/restart/60000/restart/60000
sc failureflag DartWinDivertService 1

sc delete DartWinDivertService
sc query DartWinDivertService
