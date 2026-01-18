package main

// PayloadMeta define la información de inteligencia para cada vector de ataque
type PayloadMeta struct {
	Description string // Mecanismo técnico y prerrequisitos
	OpSec       string // Nivel de detección (🟢 Stealth / 🟠 Medio / 🔴 Ruidoso)
	Consejo     string // Tip de uso o indicador de detección
}

// PayloadHelp mapea cada payload con su información de inteligencia
var PayloadHelp = map[string]PayloadMeta{

	// ==========================================
	// 🐧 LINUX / UNIX PAYLOADS
	// ==========================================

	"Bash -i": {
		Description: "Shell interactiva estándar. Requiere que '/bin/bash' exista.",
		OpSec:       "🟠 Medio: Deja rastro en .bash_history y procesos. Monitorizado por EDRs.",
		Consejo:     "Si se cierra, intenta la versión Python PTY para estabilidad.",
	},
	"Bash 196": {
		Description: "Variante usando descriptor de archivo 196 para evitar flag '-i'.",
		OpSec:       "🟢 Stealth: Puede evadir reglas simples de detección de argumentos.",
		Consejo:     "Útil en entornos restringidos donde -i está flagueado.",
	},
	"Bash read line": {
		Description: "Loop de lectura de línea. No es una shell real, solo ejecuta comandos.",
		OpSec:       "🟠 Medio: Alto uso de CPU si el loop falla. Ruidoso en logs de procesos.",
		Consejo:     "Úsalo solo si no puedes establecer una sesión interactiva.",
	},
	"Bash 5": {
		Description: "Sintaxis específica para versiones modernas de Bash.",
		OpSec:       "🟠 Medio: Comportamiento estándar de redirección.",
		Consejo:     "Verifica la versión de bash con 'bash --version' antes.",
	},
	"Bash udp": {
		Description: "Usa /dev/udp nativo de Bash. Requiere listener UDP (nc -u).",
		OpSec:       "🟢 Stealth: El tráfico UDP suele estar menos monitorizado que TCP.",
		Consejo:     "Recuerda poner tu listener en modo UDP: 'nc -u -lvnp <port>'.",
	},
	"nc mkfifo": {
		Description: "Técnica clásica usando 'named pipes' cuando netcat no tiene -e.",
		OpSec:       "🟠 Medio: Crea archivo '/tmp/f' en disco. Detectable por FIM.",
		Consejo:     "Si falla, verifica permisos de escritura en /tmp o usa /dev/shm.",
	},
	"nc -e": {
		Description: "Ejecución directa. Solo funciona en versiones antiguas o 'gaping' de netcat.",
		OpSec:       "🟠 Medio: Argumento '-e' es altamente sospechoso en logs de procesos.",
		Consejo:     "Raro en Linux modernos. Prueba 'nc mkfifo' primero.",
	},
	"BusyBox nc -e": {
		Description: "Específico para sistemas embebidos (Routers, IoT) con BusyBox.",
		OpSec:       "🟠 Medio: Común en dispositivos IoT comprometidos.",
		Consejo:     "El estándar en auditorías de hardware/IoT.",
	},
	"nc -c": {
		Description: "Variante que usa el flag '-c' (shell command) en lugar de '-e'.",
		OpSec:       "🟠 Medio: Igual que nc -e, depende de la compilación de netcat.",
		Consejo:     "Alternativa si -e falla pero la versión de nc lo soporta.",
	},
	"ncat -e": {
		Description: "Usa Ncat (del paquete Nmap), más moderno y robusto.",
		OpSec:       "🔴 Ruidoso: Ncat no suele estar instalado por defecto. Binario sospechoso.",
		Consejo:     "Soporta cifrado SSL si se configura, mejorando el OpSec.",
	},
	"ncat udp": {
		Description: "Versión UDP usando Ncat y tuberías.",
		OpSec:       "🟢 Stealth: Evasión de reglas de firewall TCP.",
		Consejo:     "Requiere listener UDP.",
	},
	"curl": {
		Description: "Descarga un script shell y lo pipea a bash.",
		OpSec:       "🔴 Ruidoso: Petición HTTP saliente + ejecución de script.",
		Consejo:     "Revisa logs de proxy/DNS para detectar la descarga.",
	},
	"rustcat": {
		Description: "Requiere el binario 'rcat' instalado en la víctima.",
		OpSec:       "🔴 Ruidoso: Binario no estándar.",
		Consejo:     "Solo útil si has comprometido el sistema previamente e instalado herramientas.",
	},
	"Haskell #1": {
		Description: "Compila/Ejecuta código Haskell. Requiere GHC instalado.",
		OpSec:       "🟢 Stealth: Lenguaje inusual, pocos EDRs buscan patrones Haskell.",
		Consejo:     "Raro encontrar el compilador en servidores de producción.",
	},
	"OpenSSL": {
		Description: "Shell cifrada SSL/TLS estándar. Evade inspección de tráfico (DPI).",
		OpSec:       "🟢 Stealth (Red): Tráfico cifrado. 🟠 Medio (Host): Uso de mkfifo.",
		Consejo:     "Necesitas generar certificado en tu listener: 'openssl req -x509...'.",
	},
	"Perl": {
		Description: "Script Perl usando Socket. Funciona en casi todos los Linux antiguos.",
		OpSec:       "🟠 Medio: Procesos 'perl' con sockets abiertos son sospechosos.",
		Consejo:     "Excelente compatibilidad legacy.",
	},
	"Perl no sh": {
		Description: "Variante Perl que no invoca /bin/sh explícitamente.",
		OpSec:       "🟢 Stealth: Evade algunas reglas de monitoreo de procesos hijos.",
		Consejo:     "Más robusto contra reglas de auditoría simples.",
	},
	"Perl PentestMonkey": {
		Description: "Script robusto, maneja variables de entorno. Clásico de CTFs.",
		OpSec:       "🟠 Medio: Código muy conocido, firmas estáticas lo detectan.",
		Consejo:     "Fiable, pero viejo.",
	},
	"PHP PentestMonkey": {
		Description: "La reverse shell PHP más famosa. Requiere subir archivo .php.",
		OpSec:       "🔴 Ruidoso: Archivo en disco. Firma conocida por todos los AVs.",
		Consejo:     "Úsala solo si puedes subir archivos al webroot.",
	},
	"PHP Ivan Sincek": {
		Description: "Variante moderna usando proc_open, maneja mejor los pipes.",
		OpSec:       "🟠 Medio: Menos detectada que PentestMonkey, pero sigue siendo PHP.",
		Consejo:     "Buena alternativa si la anterior es borrada por el AV.",
	},
	"PHP cmd": {
		Description: "Webshell de una línea (GET param). No es reverse shell, es RCE.",
		OpSec:       "🟢 Stealth: Solo una línea en un archivo existente. Difícil de ver.",
		Consejo:     "Ideal para persistencia ligera. Ejecuta: file.php?cmd=id",
	},
	"PHP cmd 2": {
		Description: "Webshell que formatea la salida con saltos de línea HTML.",
		OpSec:       "🟢 Stealth: Igual que 'PHP cmd'.",
		Consejo:     "Mejor visibilidad en el navegador.",
	},
	"PHP cmd small": {
		Description: "La webshell PHP más corta posible (Short tags).",
		OpSec:       "🟢 Stealth: Muy fácil de ocultar dentro de código legítimo.",
		Consejo:     "Requiere 'short_open_tag=On' en php.ini.",
	},
	"PHP exec": {
		Description: "One-liner usando exec().",
		OpSec:       "🟠 Medio: exec() suele estar deshabilitado en php.ini seguros.",
		Consejo:     "Verifica disable_functions antes.",
	},
	"PHP shell_exec": {
		Description: "One-liner usando shell_exec().",
		OpSec:       "🟠 Medio: Igual que exec().",
		Consejo:     "Alternativa común si exec está bloqueado.",
	},
	"PHP system": {
		Description: "One-liner usando system(). Muestra output directo.",
		OpSec:       "🟠 Medio: Muy común en logs de errores si falla.",
		Consejo:     "Útil para debug.",
	},
	"PHP passthru": {
		Description: "One-liner usando passthru(). Para datos binarios.",
		OpSec:       "🟠 Medio: Similar a system().",
		Consejo:     "Úsalo si esperas output binario.",
	},
	"PHP `": {
		Description: "Uso de backticks (operador de ejecución).",
		OpSec:       "🟢 Stealth: Sintaxis a veces ignorada por WAFs simples.",
		Consejo:     "Es un alias de shell_exec().",
	},
	"PHP popen": {
		Description: "Usa punteros a archivos (pipes).",
		OpSec:       "🟢 Stealth: A veces permitido cuando exec/system están bloqueados.",
		Consejo:     "Técnica de evasión de restricciones php.ini.",
	},
	"PHP proc_open": {
		Description: "La forma más compleja y potente de ejecutar comandos en PHP.",
		OpSec:       "🟢 Stealth: Difícil de bloquear sin romper aplicaciones legítimas.",
		Consejo:     "El 'Go-to' para entornos PHP endurecidos.",
	},
	"P0wny Shell (Webshell)": {
		Description: "Webshell UI completa en un solo archivo PHP. Emula terminal.",
		OpSec:       "🔴 Ruidoso: Archivo grande, firmas obvias. Deja logs de acceso.",
		Consejo:     "Excelente para manejo cómodo, pero poco discreta.",
	},
	"Python #1": {
		Description: "Estándar usando librería socket y subprocess.",
		OpSec:       "🟢 Stealth: Se ejecuta en memoria si se inyecta. Poco ruidoso.",
		Consejo:     "Funciona en Python 2. Para Py3 usa las específicas.",
	},
	"Python #2": {
		Description: "Variante que importa 'pty' para spawnear una TTY.",
		OpSec:       "🟢 Stealth: Crea una shell totalmente interactiva (su, vi, top).",
		Consejo:     "Imprescindible para estabilidad. La mejor opción en Linux.",
	},
	"Python3 #1": {
		Description: "Versión estándar adaptada para sintaxis Python 3.",
		OpSec:       "🟢 Stealth: Igual que Python #1.",
		Consejo:     "La mayoría de servidores modernos solo tienen python3.",
	},
	"Python3 #2": {
		Description: "Versión Python 3 con PTY (Terminal interactiva).",
		OpSec:       "🟢 Stealth: Alta estabilidad.",
		Consejo:     "El estándar de oro actual en Linux.",
	},
	"Python3 shortest": {
		Description: "One-liner de Python 3 minificado.",
		OpSec:       "🟢 Stealth: Bueno para inyecciones con límite de caracteres.",
		Consejo:     "Útil en Buffer Overflows o campos de input pequeños.",
	},
	"Ruby #1": {
		Description: "Uso de TCPSocket en Ruby.",
		OpSec:       "🟠 Medio: Depende de tener Ruby instalado.",
		Consejo:     "Común en servidores con Chef/Puppet.",
	},
	"Ruby no sh": {
		Description: "Variante Ruby sin llamar a /bin/sh directamente.",
		OpSec:       "🟢 Stealth: Evasión de monitoreo de procesos padre/hijo.",
		Consejo:     "Más discreto.",
	},
	"socat #1": {
		Description: "Conexión TCP simple con socat.",
		OpSec:       "🔴 Ruidoso: Socat es una herramienta de 'hacker' para muchos admins.",
		Consejo:     "Si está instalado, es muy potente.",
	},
	"socat #2 (TTY)": {
		Description: "Shell TTY completa. Maneja Ctrl+C y comandos interactivos.",
		OpSec:       "🔴 Ruidoso: Binario socat.",
		Consejo:     "La shell más estable posible. Listener: 'socat file:`tty`,raw,echo=0 tcp-listen:xxx'",
	},
	"sqlite3 nc mkfifo": {
		Description: "Abuso de la capacidad de sqlite3 para ejecutar comandos shell.",
		OpSec:       "🟢 Stealth: Se esconde tras un proceso de base de datos legítimo.",
		Consejo:     "Técnica LOLBin (Living Off The Land).",
	},
	"node.js": {
		Description: "Ejecución mediante child_process de Node.",
		OpSec:       "🟠 Medio: Proceso 'node' abriendo sockets raros.",
		Consejo:     "Común en entornos Cloud/Container.",
	},
	"node.js #2": {
		Description: "Payload JS puro sin depender de /bin/sh para el socket.",
		OpSec:       "🟢 Stealth: Más difícil de detectar que el exec simple.",
		Consejo:     "Mejor opción para servidores Node.",
	},
	"Javascript": {
		Description: "Generalmente para inyecciones XSS o entornos JScript.",
		OpSec:       "Varia: Depende del contexto de ejecución.",
		Consejo:     "Contexto específico.",
	},
	"telnet": {
		Description: "Reverse shell antigua usando dos pipes de telnet.",
		OpSec:       "🔴 Ruidoso: Telnet envía todo en texto plano. Muy visible.",
		Consejo:     "Último recurso si no hay nc/python/bash.",
	},
	"zsh": {
		Description: "Uso del módulo ztcp de Zsh.",
		OpSec:       "🟢 Stealth: Zsh es común en macOS y devs. Tráfico parece legítimo.",
		Consejo:     "Potente en estaciones de trabajo de desarrolladores.",
	},
	"Lua #1": {
		Description: "Lua socket script. Común en servidores Nginx/Redis.",
		OpSec:       "🟠 Medio: Requiere librerías socket de Lua.",
		Consejo:     "Verifica si 'os.execute' está permitido.",
	},
	"Lua #2": {
		Description: "Variante Lua 5.1 pura.",
		OpSec:       "🟠 Medio: Igual que Lua #1.",
		Consejo:     "Adaptado para versiones antiguas.",
	},
	"Golang": {
		Description: "Compila y ejecuta código Go al vuelo en /tmp.",
		OpSec:       "🟠 Medio: Deja archivos .go y binarios en /tmp.",
		Consejo:     "Requiere entorno 'go' instalado (común en devs).",
	},
	"Vlang": {
		Description: "Similar a Go, para el lenguaje V.",
		OpSec:       "🟠 Medio: Requiere compilador V.",
		Consejo:     "Muy específico.",
	},
	"Awk": {
		Description: "Reverse shell usando funciones de red internas de Gawk.",
		OpSec:       "🟢 Stealth: Awk es una herramienta benigna de sistema.",
		Consejo:     "Funciona incluso en sistemas minimalistas.",
	},
	"Crystal (system)": {
		Description: "Ejecución comando sistema en Crystal.",
		OpSec:       "🟠 Medio: Requiere compilador.",
		Consejo:     "Poco común.",
	},
	"Crystal (code)": {
		Description: "Código nativo Crystal.",
		OpSec:       "🟠 Medio: Requiere compilador.",
		Consejo:     "Poco común.",
	},
	"JSP Simple (Bash)": {
		Description: "JSP que invoca una reverse shell de Bash.",
		OpSec:       "🔴 Ruidoso: Archivo .jsp en disco + proceso bash hijo de java.",
		Consejo:     "Detectado por cualquier EDR decente.",
	},
	"Msfvenom (ELF)": {
		Description: "Binario Linux generado por Metasploit.",
		OpSec:       "🔴 Muy Ruidoso: Firmas de Meterpreter son conocidas mundialmente.",
		Consejo:     "Solo úsalo si has ofuscado el binario o deshabilitado el AV.",
	},
	"DNS Tunneling (dnscat2)": {
		Description: "Túnel C2 sobre consultas DNS.",
		OpSec:       "🟢 Stealth: Evade firewalls que bloquean TCP/UDP directo.",
		Consejo:     "Lento, pero sale de casi cualquier red aislada.",
	},
	"XSLT Injection": {
		Description: "Inyección en parsers XML/XSLT vulnerables para ejecutar PHP/Shell.",
		OpSec:       "🟢 Stealth: Ataque a nivel de aplicación, no de sistema operativo.",
		Consejo:     "Busca endpoints que procesen XML.",
	},
	"C": {
		Description: "Código fuente C. Debe ser compilado (gcc rev.c -o rev).",
		OpSec:       "🟠 Medio: Compilar en la víctima (gcc) genera alertas.",
		Consejo:     "Mejor compilar localmente y subir el binario.",
	},
	"C# TCP Client": {
		Description: "Código C# (Mono/DotNet) para Linux/Windows.",
		OpSec:       "🟠 Medio: Ejecución de binarios .NET.",
		Consejo:     "Cross-platform si hay runtime instalado.",
	},
	"C# Bash -i": {
		Description: "Wrapper C# que lanza bash.",
		OpSec:       "🟠 Medio: Proceso hijo sospechoso.",
		Consejo:     "Variante de ejecución.",
	},
	"Dart": {
		Description: "Reverse shell en Dart.",
		OpSec:       "🟠 Medio: Requiere SDK Dart.",
		Consejo:     "Entornos de desarrollo Flutter/Dart.",
	},
	"Java #1": {
		Description: "Uso de Runtime.exec para lanzar pipes de shell.",
		OpSec:       "🟠 Medio: Java lanzando shell es un patrón de detección clásico.",
		Consejo:     "Payload universal para RCE en Java.",
	},
	"Java #2": {
		Description: "Socket Java puro sin pipes de shell complejos.",
		OpSec:       "🟢 Stealth: Menos sospechoso que lanzar bash con pipes.",
		Consejo:     "Más código, pero más estable.",
	},
	"Java #3": {
		Description: "Variante completa de Java Reverse Shell.",
		OpSec:       "🟢 Stealth: Manejo de streams manual.",
		Consejo:     "Buena para inyecciones de código (Deseriliazation).",
	},
	"Java Web": {
		Description: "JSP completo con gestión de hilos para streams.",
		OpSec:       "🔴 Ruidoso: Archivo JSP en disco.",
		Consejo:     "Para persistencia en Tomcat/JBoss.",
	},
	"Java Two Way": {
		Description: "Shell Java bidireccional.",
		OpSec:       "🟢 Stealth: Puro Java, sin procesos shell hijos (a veces).",
		Consejo:     "Avanzado.",
	},

	// ==========================================
	// 🪟 WINDOWS PAYLOADS
	// ==========================================

	"nc.exe -e": {
		Description: "Usa binario Netcat Windows. Requiere subir nc.exe.",
		OpSec:       "🔴 Muy Ruidoso: nc.exe es detectado por el 99% de los AVs.",
		Consejo:     "Solo en máquinas legacy (XP/2003) o sin AV.",
	},
	"ncat.exe -e": {
		Description: "Usa binario Ncat Windows.",
		OpSec:       "🔴 Ruidoso: Igual que nc.exe.",
		Consejo:     "A veces ncat.exe está permitido por administradores.",
	},
	"PowerShell #1": {
		Description: "Shell TCP pura. No toca disco.",
		OpSec:       "🟠 Medio: AMSI (Anti-Malware Scan Interface) escanea el script.",
		Consejo:     "Estándar. Si falla, prueba la versión Base64.",
	},
	"PowerShell #2": {
		Description: "Variante con encoding UTF8 y manejo de streams.",
		OpSec:       "🟠 Medio: Patrones de ejecución conocidos.",
		Consejo:     "Alternativa si #1 se cuelga.",
	},
	"PowerShell #3 (Base64)": {
		Description: "Payload codificado en Base64 para evadir filtros de texto.",
		OpSec:       "🟢 Stealth (Filtros): Evade detección de strings, pero AMSI decodifica.",
		Consejo:     "Útil para pasar payloads por WAFs o CMDs restrictivos.",
	},
	"PowerShell #4 (TCP)": {
		Description: "Otra variante de cliente TCP directo.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Variación de sintaxis.",
	},
	"PowerShell #5 (IEX)": {
		Description: "Download Cradle: Descarga script de memoria (Invoke-WebRequest).",
		OpSec:       "🔴 Ruidoso: Genera tráfico HTTP y ejecuta código remoto.",
		Consejo:     "Requiere que hostees el payload 'shell.ps1' en tu máquina.",
	},
	"PHP PentestMonkey Windows": {
		Description: "Versión Windows (cmd.exe) del script clásico.",
		OpSec:       "🔴 Ruidoso: Archivo PHP en disco.",
		Consejo:     "Para XAMPP/IIS con PHP.",
	},
	"PHP Ivan Sincek Windows": {
		Description: "Variante proc_open para Windows.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Más estable en Windows que exec().",
	},
	"PHP cmd Windows": {
		Description: "Webshell simple Windows.",
		OpSec:       "🟢 Stealth: Mínima huella.",
		Consejo:     "RCE Básico.",
	},
	"PHP cmd 2 Windows": {
		Description: "Webshell formateada.",
		OpSec:       "🟢 Stealth.",
		Consejo:     "Visibilidad.",
	},
	"PHP cmd small Windows": {
		Description: "Short tag webshell.",
		OpSec:       "🟢 Stealth.",
		Consejo:     "Evasión.",
	},
	"PHP system Windows": {
		Description: "System() call.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Test rápido.",
	},
	"PHP backticks Windows": {
		Description: "Ejecución con backticks.",
		OpSec:       "🟢 Stealth.",
		Consejo:     "Evasión.",
	},
	"Python Windows": {
		Description: "Python invocando cmd.exe.",
		OpSec:       "🟢 Stealth: Si Python está instalado, es muy discreto.",
		Consejo:     "Raro en Windows servers, común en workstations de devs.",
	},
	"Python3 Windows": {
		Description: "Versión Python 3.",
		OpSec:       "🟢 Stealth.",
		Consejo:     "Igual que anterior.",
	},
	"Ruby Windows": {
		Description: "Ruby socket.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Requiere entorno Ruby.",
	},
	"Perl Windows": {
		Description: "Perl socket.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Común en servidores con Git bash instalado.",
	},
	"Lua Windows": {
		Description: "Lua socket.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Raro en Windows.",
	},
	"Golang Windows": {
		Description: "Compila Go en Windows.",
		OpSec:       "🟠 Medio: Requiere Go instalado.",
		Consejo:     "Poco común.",
	},
	"ConPtyShell": {
		Description: "Shell Pseudo-Consola real. Interactiva (Tab completion, colores).",
		OpSec:       "🟠 Medio: Descarga script pesado de Internet.",
		Consejo:     "La MEJOR shell para Windows si necesitas interactividad real.",
	},
	"Mshta": {
		Description: "Ejecución vía HTA (HTML Application). LOLBin.",
		OpSec:       "🟠 Medio: Proceso mshta.exe conectando a internet es sospechoso.",
		Consejo:     "Bypass de listas blancas de ejecución (AppLocker) a veces.",
	},
	"Regsvr32": {
		Description: "Ejecución de objetos COM scriptlet (.sct). LOLBin.",
		OpSec:       "🟠 Medio: Técnica conocida como 'Squiblydoo'.",
		Consejo:     "Bypass de AppLocker clásico.",
	},
	"node.js Windows": {
		Description: "Node child process a nc.exe.",
		OpSec:       "🔴 Ruidoso: Requiere nc.exe.",
		Consejo:     "Dependencia externa.",
	},
	"node.js #2 Windows": {
		Description: "Node JS socket puro.",
		OpSec:       "🟢 Stealth: Vive dentro del proceso node.exe.",
		Consejo:     "Mejor opción si Node está presente.",
	},
	"Haskell Windows": {
		Description: "Haskell cmd wrapper.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Exótico.",
	},
	"Msfvenom (EXE)": {
		Description: "Ejecutable Windows generado por Metasploit.",
		OpSec:       "🔴 Muy Ruidoso: Detectado instantáneamente por Defender.",
		Consejo:     "Necesitas 'shikata_ga_nai' o encoders personalizados.",
	},
	"HoaxShell (HTTPS Hook)": {
		Description: "Shell sobre HTTPS. Difícil de detectar por tráfico.",
		OpSec:       "🟢 Stealth (Red): Tráfico parece navegación web normal.",
		Consejo:     "Requiere el servidor HoaxShell corriendo.",
	},
	"Groovy": {
		Description: "Java/Groovy payload. Común en Jenkins.",
		OpSec:       "🟠 Medio: Ejecución dentro de la JVM.",
		Consejo:     "Vector principal de ataque a Jenkins CI/CD.",
	},
	"C Windows": {
		Description: "Código C nativo Win32 API.",
		OpSec:       "🟠 Medio: Requiere compilación.",
		Consejo:     "Base para crear malware custom.",
	},
	"C# TCP Client Windows": {
		Description: "Código C# fuente.",
		OpSec:       "🟠 Medio: Compilación dinámica csc.exe.",
		Consejo:     "Potente.",
	},
	"C# PowerShell": {
		Description: "C# que invoca un runspace de PowerShell.",
		OpSec:       "🟠 Medio: Evasión de monitoreo de powershell.exe directo.",
		Consejo:     "Técnica 'Unmanaged PowerShell'.",
	},
	"ASPX Shell": {
		Description: "Webshell para IIS (Internet Information Services).",
		OpSec:       "🔴 Ruidoso: Archivo .aspx en wwwroot.",
		Consejo:     "Compilado al vuelo por IIS.",
	},
	"MSBuild": {
		Description: "Ejecución de código C# inline en archivos XML de proyecto.",
		OpSec:       "🟠 Medio: Proceso MSBuild.exe iniciando conexiones es anómalo.",
		Consejo:     "Gran técnica de evasión de Whitelisting.",
	},
	"Java Windows": {
		Description: "Reverse shell Java en entorno Windows.",
		OpSec:       "🟠 Medio.",
		Consejo:     "Igual que Linux pero invocando cmd.exe.",
	},
}
