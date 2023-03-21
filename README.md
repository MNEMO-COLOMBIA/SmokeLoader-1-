# SmokeLoader-1-
Esta regla identifica archivos ejecutables que contienen tres características:
La cadena "SmoKeloader" en formato wide ascii, que es una cadena que el malware utiliza para identificarse.
La presencia de las bibliotecas de enlace dinámico (DLL) "advapi32.dll" y "kernel32.dll", que son comunes en las actividades maliciosas.
La presencia de las funciones de Windows "VirtualAlloc", "GetProcAddress" y "LoadLibraryA", que son utilizadas por el malware para alojar código malicioso en la memoria del sistema y ejecutarlo.
