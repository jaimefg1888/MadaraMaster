## 🇬🇧 English

# 🧹 MadaraMaster

Secure file destruction tool. MadaraMaster overwrites files following NIST SP 800-88 and DoD 5220.22-M standards before deleting them, making recovery with conventional forensic tools impossible.

---

## Features

- **Automatic storage detection** — distinguishes HDD, SSD, and NVMe on Linux, Windows, and macOS and adjusts the strategy accordingly.
- **Async engine** built with `aiofiles` and adaptive buffers (50 MB for SSD/NVMe, 10 MB for HDD).
- **Direct I/O** — bypasses the OS page cache (`O_DIRECT | O_SYNC` on Linux; `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` on Windows) to ensure wiped data is never silently re-cached.
- **Slack space destruction** — overwrites the gap between file EOF and the cluster boundary with random bytes.
- **ADS destruction** (Windows only) — enumerates and wipes every Alternate Data Stream via `FindFirstStreamW` / `FindNextStreamW`.
- **Inode metadata scrubbing** — zeros all MAC timestamps and performs 3–5 renames with variable-length names to overwrite MFT / ext4 journal entries.
- **Optional `--verify` flag** — samples random blocks after wiping and checks Shannon entropy; below 7.0 bits/byte marks the operation as failed.
- **Audit log** — every operation is recorded in `madara_audit.jsonl` with pre-wipe SHA-256, UTC timestamps, user, hostname, and result.
- **Interactive session** — argumentless mode where you can drag files into the terminal, queue them, and wipe them all at once.

## Requirements

- Python 3.10+
- `typer >= 0.9.0`
- `rich >= 13.7.0`
- `aiofiles >= 23.2.1`

## Setup

```bash
git clone https://github.com/jaimefg1888/MadaraMaster
cd MadaraMaster
pip install -r requirements.txt
```

## Run it

### Interactive mode

```bash
python madara.py
```

Select language at startup, then drag files or type paths. Press Enter with a non-empty queue to start wiping.

### CLI

```bash
python madara.py wipe secret.pdf
python madara.py wipe /path/to/directory
python madara.py wipe secret.pdf --confirm
python madara.py wipe /path --dry-run
python madara.py wipe data.pdf --standard purge --verify
python madara.py wipe data.pdf --log-path /var/log/madara_audit.jsonl
```

### Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--confirm` | `-y` | Skip confirmation prompt |
| `--dry-run` | `-n` | Preview targets without wiping |
| `--standard` | `-s` | `clear`, `purge`, or `dod` |
| `--verify` | `-v` | Verify Shannon entropy after wipe |
| `--log-path` | `-l` | Custom path for the audit log |

### Standards

| Standard | Passes | When to use |
|----------|--------|-------------|
| `clear` | 1 | General use, non-critical data |
| `purge` | 3 + verify | Sensitive data |
| `dod` | 3 | DoD 5220.22-M compatibility |

On SSDs and NVMe drives, one cryptographic-random pass is always applied regardless of the chosen standard (NIST SP 800-88 Rev. 1 §2.4).

## Project structure

```
MadaraMaster/
├── madara.py           # CLI entry point + live dashboard
├── wiper.py            # Synchronous wipe engine (DoD 5220.22-M)
├── wiper_async.py      # Async wipe engine (Direct I/O, ADS, slack space)
├── storage.py          # Storage-type detection (Linux sysfs / Windows ctypes / macOS diskutil)
├── trim.py             # TRIM/Discard dispatch (Linux FITRIM / Windows DMDSA)
├── audit.py            # Forensic audit logger (JSON Lines)
├── utils.py            # Formatting utilities
├── requirements.txt
├── Dockerfile
└── README.md
```

## License

MIT. See the LICENSE file.

This software is provided for authorized data sanitization use only. The author takes no responsibility for misuse or data loss from incorrect usage.

---

## 🇪🇸 Español

# 🧹 MadaraMaster

Herramienta de destrucción segura de archivos. MadaraMaster sobrescribe archivos siguiendo los estándares NIST SP 800-88 y DoD 5220.22-M antes de eliminarlos, de forma que no puedan recuperarse con herramientas forenses convencionales.

---

## Características

- **Detección automática de almacenamiento** — distingue HDD, SSD y NVMe en Linux, Windows y macOS y ajusta la estrategia en consecuencia.
- **Motor async** con `aiofiles` y buffers adaptativos (50 MB en SSD/NVMe, 10 MB en HDD).
- **Direct I/O** — evita la caché de páginas del SO (`O_DIRECT | O_SYNC` en Linux; `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` en Windows) para garantizar que los datos borrados no queden en RAM.
- **Destrucción del slack space** — sobrescribe el espacio entre EOF y el límite del clúster con bytes aleatorios.
- **Destrucción de ADS** (solo Windows) — enumera y machaca cada Alternate Data Stream mediante `FindFirstStreamW` / `FindNextStreamW`.
- **Limpieza de metadatos de inodo** — pone a cero todos los timestamps MAC y realiza 3–5 renombrados con nombres de longitud variable para machacar entradas de la MFT / journal ext4.
- **Flag `--verify` opcional** — muestrea bloques aleatorios tras el borrado y comprueba la entropía Shannon; por debajo de 7.0 bits/byte marca la operación como fallida.
- **Log de auditoría** — cada operación queda registrada en `madara_audit.jsonl` con SHA-256 pre-borrado, timestamps UTC, usuario, hostname y resultado.
- **Sesión interactiva** — modo sin argumentos donde puedes arrastrar archivos a la terminal, hacer cola y borrarlos todos de golpe.

## Requisitos

- Python 3.10+
- `typer >= 0.9.0`
- `rich >= 13.7.0`
- `aiofiles >= 23.2.1`

## Instalación

```bash
git clone https://github.com/jaimefg1888/MadaraMaster
cd MadaraMaster
pip install -r requirements.txt
```

## Ejecutar

### Modo interactivo

```bash
python madara.py
```

Selecciona idioma al arrancar, luego arrastra archivos o escribe rutas. Pulsa Enter con la cola llena para iniciar el borrado.

### CLI

```bash
python madara.py wipe secreto.pdf
python madara.py wipe /ruta/directorio
python madara.py wipe secreto.pdf --confirm
python madara.py wipe /ruta --dry-run
python madara.py wipe datos.pdf --standard purge --verify
python madara.py wipe datos.pdf --log-path /var/log/madara_audit.jsonl
```

### Opciones

| Opción | Alias | Descripción |
|--------|-------|-------------|
| `--confirm` | `-y` | Saltar confirmación |
| `--dry-run` | `-n` | Vista previa sin borrar |
| `--standard` | `-s` | `clear`, `purge` o `dod` |
| `--verify` | `-v` | Verificar entropía post-borrado |
| `--log-path` | `-l` | Ruta para el log de auditoría |

### Estándares

| Estándar | Pases | Cuándo usarlo |
|----------|-------|---------------|
| `clear` | 1 | Uso general, datos no críticos |
| `purge` | 3 + verificación | Datos sensibles |
| `dod` | 3 | Compatibilidad DoD 5220.22-M |

En SSD y NVMe siempre se aplica 1 pase aleatorio criptográfico independientemente del estándar elegido (NIST SP 800-88 Rev. 1 §2.4).

## Estructura del proyecto

```
MadaraMaster/
├── madara.py           # CLI + dashboard en vivo
├── wiper.py            # Motor síncrono (DoD 5220.22-M)
├── wiper_async.py      # Motor asíncrono (Direct I/O, ADS, slack space)
├── storage.py          # Detección de almacenamiento (sysfs / ctypes / diskutil)
├── trim.py             # Envío de TRIM/Discard (Linux FITRIM / Windows DMDSA)
├── audit.py            # Log forense (JSON Lines)
├── utils.py            # Utilidades de formato
├── requirements.txt
├── Dockerfile
└── README.md
```

## Licencia

MIT. Consulta el archivo LICENSE.

El software se proporciona para uso autorizado de destrucción segura de datos. El autor no se hace responsable del mal uso ni de pérdida de datos por uso incorrecto.
