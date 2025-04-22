# VulnOSINT Scanner v1.0

## Desarrollador
Christian Duran

## Descripción
VulnOSINT Scanner es una herramienta de seguridad informática diseñada para la identificación y análisis de vulnerabilidades en sistemas operativos y aplicaciones, combinado con capacidades avanzadas de OSINT (Open Source Intelligence). Esta herramienta permite realizar evaluaciones de seguridad tanto en sistemas locales como en objetivos remotos.

## ⚠️ Aviso Legal
Esta herramienta ha sido desarrollada con fines educativos y de investigación. El uso indebido de esta herramienta para acceder sin autorización a sistemas informáticos puede constituir un delito en muchas jurisdicciones. El desarrollador no se hace responsable del mal uso que se pueda hacer de esta herramienta.

## Características Principales

### Análisis de Vulnerabilidades
- **Escaneo de Sistemas Locales**: Detecta configuraciones inseguras, servicios vulnerables y puertos abiertos en el sistema.
- **Análisis de Sistemas Remotos**: Identifica servicios y versiones potencialmente vulnerables en objetivos remotos.
- **Comprobación de Contraseñas**: Verifica la presencia de políticas de contraseñas débiles (simulado).

### Capacidades OSINT
- **Información de Dominio**: Recopila datos WHOIS, registros DNS y otra información pública.
- **Análisis de Tecnologías Web**: Identifica servidores, frameworks y otras tecnologías utilizadas en sitios web.
- **Huella Digital**: Determina la huella digital de servicios y aplicaciones expuestas.

### Generación de Informes
- **Informes Detallados**: Crea reportes completos sobre las vulnerabilidades encontradas y la información OSINT recopilada.
- **Exportación en Varios Formatos**: Almacena resultados en formatos JSON y TXT para posterior análisis.
- **Recomendaciones de Seguridad**: Proporciona sugerencias específicas para mejorar la seguridad.

## Requisitos
- Python 3.7 o superior
- Sistema operativo: Windows, Linux o macOS
- Conexión a Internet para funciones OSINT
- Privilegios de administrador para algunas funciones de análisis local

## Dependencias
```
pip install -r requirements.txt
```

Contenido de `requirements.txt`:
```
requests
python-whois
dnspython
python-nmap
psutil
colorama
```

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/christianduran/vulnosint-scanner.git
cd vulnosint-scanner
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Otorgar permisos de ejecución (solo en sistemas Unix):
```bash
chmod +x vulnosint_scanner.py
```

## Uso

### Comandos Básicos

```bash
# Escaneo completo de un dominio remoto
python vulnosint_scanner.py -t ejemplo.com

# Escaneo del sistema local
python vulnosint_scanner.py -l

# Escaneo combinado (sistema local y objetivo remoto)
python vulnosint_scanner.py -t ejemplo.com -l

# Solo análisis OSINT de un dominio
python vulnosint_scanner.py -t ejemplo.com --osint

# Solo análisis de vulnerabilidades
python vulnosint_scanner.py -t ejemplo.com --vuln
```

### Parámetros

| Parámetro | Descripción |
|-----------|-------------|
| `-t, --target` | IP o dominio objetivo para analizar |
| `-l, --local` | Realiza un escaneo del sistema local |
| `--osint` | Realiza solo análisis OSINT (requiere especificar un dominio) |
| `--vuln` | Realiza solo análisis de vulnerabilidades |

## Estructura de Resultados

Los resultados se almacenan en el directorio `security_scan_results/` creado en el directorio de ejecución:

- `scan_results_[timestamp].json`: Contiene todos los datos recopilados durante el análisis en formato JSON.
- `security_report_[timestamp].txt`: Informe legible con un resumen de los hallazgos y recomendaciones.

## Ejemplos de Uso

### Análisis de Dominio
```bash
python vulnosint_scanner.py -t example.com
```
Este comando realizará:
1. Recopilación de información OSINT sobre el dominio
2. Resolución del dominio a IP y escaneo de puertos
3. Análisis de vulnerabilidades en los servicios detectados
4. Generación de un informe completo

### Análisis de Sistema Local
```bash
python vulnosint_scanner.py -l
```
Este comando analizará:
1. Usuarios y permisos del sistema
2. Actualizaciones pendientes de seguridad
3. Servicios en ejecución y puertos abiertos
4. Configuraciones de seguridad básicas

## Capturas de Pantalla

![Escaneo de Sistema](https://via.placeholder.com/600x300?text=Escaneo+de+Sistema)
*Ejemplo de escaneo de sistema local*

![Análisis OSINT](https://via.placeholder.com/600x300?text=Análisis+OSINT)
*Ejemplo de recolección de información OSINT*

## Limitaciones

- El análisis de vulnerabilidades se basa en detecciones de versión y no realiza comprobaciones de explotación.
- Algunas funciones requieren privilegios elevados para ser efectivas.
- La herramienta no realiza evaluaciones exhaustivas de todas las posibles vulnerabilidades.
- El análisis OSINT está limitado a fuentes públicas y gratuitas.

## Desarrollo Futuro

- Incorporación de bases de datos de vulnerabilidades (CVE)
- Integración con servicios OSINT adicionales
- Implementación de análisis dinámico de aplicaciones web
- Soporte para escaneo de redes más amplio
- Interfaz gráfica para facilitar su uso

## Contribuir

Las contribuciones son bienvenidas. Para contribuir:

1. Hacer fork del repositorio
2. Crear una rama para la nueva característica (`git checkout -b feature/nueva-caracteristica`)
3. Hacer commit de los cambios (`git commit -am 'Añadir nueva característica'`)
4. Hacer push a la rama (`git push origin feature/nueva-caracteristica`)
5. Crear un Pull Request

## Licencia

Copyright © 2025 Christian Duran. Todos los derechos reservados.

Este software es propiedad de Christian Duran y su uso y distribución están sujetos a los términos establecidos por el autor. No se permite la redistribución, modificación o uso comercial sin permiso explícito.


*Este README fue actualizado por última vez el 21 de abril de 2025.*
