#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
╔══════════════════════════════════════════════════════════════════╗
║          SISTEMA DE VIGILANCIA INTELIGENTE v2.0                 ║
║   Reconocimiento: Caras · Vehículos · Placas                    ║
║   3 Cámaras RTSP · Servidor Web Seguro · Auto-limpieza 25GB     ║
╚══════════════════════════════════════════════════════════════════╝

EJECUCIÓN:  Doble clic en INICIAR_VIGILANCIA.bat
            O desde CMD/PowerShell: python vigilancia_sistema.py
El script se auto-instala, crea carpetas y levanta todo solo.
Unidad de almacenamiento: D:\CAMARAS
"""

import sys
import os
import subprocess
import importlib
import platform
import secrets
import hashlib
import hmac
import json
import time
import threading
import queue
import logging
import shutil
import sqlite3
import struct
import socket
import base64
import re
import math
import signal
import traceback
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from functools import wraps
from io import BytesIO

# ── Configuración de consola Windows ────────────────────────────
if platform.system() == "Windows":
    # Forzar UTF-8 en la consola de Windows
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    # Configurar stdout/stderr en UTF-8
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    os.environ["PYTHONIOENCODING"] = "utf-8"
    os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp"

# ══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN PRINCIPAL — EDITAR ANTES DE EJECUTAR
# ══════════════════════════════════════════════════════════════════

CONFIG = {
    # Ruta del disco externo donde se guardarán las grabaciones
    "disco_externo": "D:\\",                         # Unidad D: (disco externo)

    # Nombre de la carpeta principal dentro del disco externo
    "carpeta_base": "CAMARAS",

    # ── Cámaras RTSP ──────────────────────────────────────────────
    # Configurar cada cámara. Formato RTSP Tapo:
    # rtsp://usuario:contraseña@IP:554/stream1
    "camaras": [
        {
            "id": 1,
            "nombre": "Camara_Entrada",
            "url": "rtsp://admin:password@192.168.1.100:554/stream1",
            "activa": True,
            "guardar_personas": True,
            "guardar_vehiculos": True,
            "guardar_placas": True,
            "descripcion": "Cámara frontal entrada principal"
        },
        {
            "id": 2,
            "nombre": "Camara_Estacionamiento",
            "url": "rtsp://admin:password@192.168.1.101:554/stream1",
            "activa": True,
            "guardar_personas": True,
            "guardar_vehiculos": True,
            "guardar_placas": True,
            "descripcion": "Cámara estacionamiento y vehículos"
        },
        {
            "id": 3,
            "nombre": "Camara_Interior",
            "url": "rtsp://admin:password@192.168.1.102:554/stream1",
            "activa": True,
            "guardar_personas": True,      # Solo personas
            "guardar_vehiculos": False,    # Sin vehículos
            "guardar_placas": False,       # Sin placas
            "descripcion": "Cámara interior — solo personas"
        }
    ],

    # ── Servidor Web ──────────────────────────────────────────────
    # Máxima privacidad por defecto: solo abre el panel en esta PC.
    # Para verlo desde otro dispositivo de tu Wi-Fi, cambia a la IP local de esta PC
    # (ej. "192.168.101.27") y permite Python en el Firewall de Windows solo en red privada.
    "web_host": "127.0.0.1",
    "web_port": 8443,
    "web_ssl": True,              # True = HTTPS local con certificado auto-firmado

    # Privacidad: por defecto NO instala ni descarga nada de internet al arrancar.
    # Instala dependencias/modelos manualmente una vez, y luego mantenlo en False.
    "auto_instalar_dependencias": False,
    "permitir_descargas_modelos": False,
    "permitir_rtsp_fuera_lan": False,     # Bloquea URLs de cámaras que no sean IP privada/local
    "ocultar_credenciales_logs": True,    # No imprime usuario/contraseña RTSP en consola/logs
    "forzar_https": True,                 # Rechaza peticiones HTTP si SSL está activo

    # ── Almacenamiento ────────────────────────────────────────────
    "max_gb_total": 25,           # Máximo GB en disco externo
    "limpieza_cada_min": 30,      # Revisar espacio cada N minutos
    "imagen_calidad": 85,         # Calidad JPEG (1-100)
    "guardar_cada_seg": 2,        # Intervalo mínimo entre capturas del mismo objeto

    # ── Detección ─────────────────────────────────────────────────
    "fps_proceso": 5,             # FPS a procesar (original puede ser 25fps)
    "confianza_cara": 0.6,        # Umbral confianza detección cara
    "confianza_vehiculo": 0.5,    # Umbral confianza detección vehículo
    "confianza_placa": 0.4,       # Umbral confianza OCR placa

    # ── Sesión web ────────────────────────────────────────────────
    "sesion_timeout_min": 60,     # Minutos hasta expirar sesión
    "max_intentos_login": 5,      # Intentos antes de bloquear IP
    "bloqueo_min": 30,            # Minutos de bloqueo tras fallos
}

# ══════════════════════════════════════════════════════════════════
# FASE 1: AUTO-INSTALACIÓN DE DEPENDENCIAS
# ══════════════════════════════════════════════════════════════════

PAQUETES_REQUERIDOS = {
    "cv2": "opencv-python",
    "numpy": "numpy",
    "flask": "flask",
    "PIL": "Pillow",
    "cryptography": "cryptography",
    "werkzeug": "werkzeug",
    "imutils": "imutils",
}

PAQUETES_OPCIONALES = {
    "ultralytics": "ultralytics",      # YOLOv8 para detección
    "easyocr": "easyocr",              # OCR para placas
    "flask_limiter": "flask-limiter",  # Rate limiting
}

def instalar_paquete(paquete_pip: str) -> bool:
    """Instala un paquete pip automáticamente."""
    try:
        print(f"  -> Instalando {paquete_pip}...", end=" ", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", paquete_pip, "--quiet", "--upgrade"],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0:
            print("OK")
            return True
        else:
            print(f"ERROR ({result.stderr[:100]})")
            return False
    except subprocess.TimeoutExpired:
        print("ERROR (timeout)")
        return False
    except Exception as e:
        print(f"ERROR ({e})")
        return False

def verificar_e_instalar_dependencias():
    """Verifica todas las dependencias e instala las faltantes."""
    print("\n" + "═" * 60)
    print("  VERIFICANDO DEPENDENCIAS")
    print("═" * 60)

    faltantes = []
    for modulo, pip_name in PAQUETES_REQUERIDOS.items():
        try:
            importlib.import_module(modulo)
            print(f"  [OK] {pip_name}")
        except ImportError:
            faltantes.append(pip_name)
            print(f"  [--] {pip_name} --- instalando...")

    if faltantes:
        print(f"\n  Instalando {len(faltantes)} paquete(s) requerido(s)...")
        # Upgrade pip primero
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
                       capture_output=True)
        for pkg in faltantes:
            if not instalar_paquete(pkg):
                print(f"\n  ERROR FATAL: No se pudo instalar {pkg}")
                print(f"  Ejecuta manualmente: pip install {pkg}")
                input("  Presiona Enter para salir...")
                sys.exit(1)

    print("\n  Dependencias opcionales (para mejor deteccion):")
    for modulo, pip_name in PAQUETES_OPCIONALES.items():
        try:
            importlib.import_module(modulo)
            print(f"  [OK] {pip_name}")
        except ImportError:
            print(f"  [  ] {pip_name} --- instalando (puede tardar)...")
            instalar_paquete(pip_name)

    print("\n  [OK] Todas las dependencias listas\n")

# Ejecutar auto-instalación ANTES de importar solo si se permite en CONFIG.
# Recomendado para privacidad: mantener False después de la primera instalación manual.
if CONFIG.get("auto_instalar_dependencias", False):
    verificar_e_instalar_dependencias()
else:
    print("\n[PRIVACIDAD] Auto-instalación desactivada. No se descargará nada con pip.\n")

# ── Ahora importar todo ──────────────────────────────────────────
import cv2
import numpy as np
from PIL import Image
import flask
from flask import Flask, request, jsonify, session, send_file, redirect, url_for, render_template_string, make_response
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    SSL_DISPONIBLE = True
except ImportError:
    SSL_DISPONIBLE = False

try:
    from ultralytics import YOLO
    YOLO_DISPONIBLE = True
except ImportError:
    YOLO_DISPONIBLE = False

try:
    import easyocr
    OCR_DISPONIBLE = True
except ImportError:
    OCR_DISPONIBLE = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_DISPONIBLE = True
except ImportError:
    LIMITER_DISPONIBLE = False

# ══════════════════════════════════════════════════════════════════
# FASE 2: ESTRUCTURA DE CARPETAS Y BASE DE DATOS
# ══════════════════════════════════════════════════════════════════

class GestorAlmacenamiento:
    """Gestiona la estructura de carpetas en el disco externo."""

    def __init__(self):
        self.base = Path(CONFIG["disco_externo"]) / CONFIG["carpeta_base"]
        self.carpetas = {
            "personas":  self.base / "01_Personas",
            "vehiculos": self.base / "02_Vehiculos",
            "placas":    self.base / "03_Placas",
            "sistema":   self.base / "sistema",
            "ssl":       self.base / "sistema" / "ssl",
            "logs":      self.base / "sistema" / "logs",
            "db":        self.base / "sistema" / "db",
        }

    def inicializar(self) -> bool:
        """Crea toda la estructura de carpetas."""
        print("=" * 60)
        print("  INICIALIZANDO ALMACENAMIENTO")
        print("=" * 60)

        # Verificar que la unidad D: exista
        disco = Path(CONFIG["disco_externo"])
        if not disco.exists():
            print(f"  ADVERTENCIA: La unidad {CONFIG['disco_externo']} no esta disponible.")
            print(f"  Verifica que el disco externo D: este conectado.")
            print(f"  Creando igualmente la estructura (se guardara cuando este disponible)...")

        # Crear todas las carpetas
        for nombre, ruta in self.carpetas.items():
            ruta.mkdir(parents=True, exist_ok=True)
            print(f"  [OK] {ruta}")

        # Subcarpetas por camara
        for cam in CONFIG["camaras"]:
            for tipo in ["personas", "vehiculos", "placas"]:
                subcarpeta = self.carpetas[tipo] / cam["nombre"]
                subcarpeta.mkdir(parents=True, exist_ok=True)

        print(f"\n  Almacenamiento en: {self.base}")
        print(f"  Limite maximo: {CONFIG['max_gb_total']} GB\n")
        return True

    def espacio_usado_gb(self) -> float:
        """Retorna GB usados en las carpetas de deteccion."""
        total = 0
        for tipo in ["personas", "vehiculos", "placas"]:
            carpeta = self.carpetas[tipo]
            if carpeta.exists():
                for ruta in carpeta.rglob("*"):
                    if ruta.is_file():
                        try:
                            total += ruta.stat().st_size
                        except OSError:
                            pass
        return total / (1024 ** 3)

    def limpiar_archivos_antiguos(self):
        """Elimina los archivos más antiguos hasta bajar del límite de 25GB."""
        max_bytes = CONFIG["max_gb_total"] * (1024 ** 3)

        # Recolectar todos los archivos de detección (no sistema)
        archivos = []
        for tipo in ["personas", "vehiculos", "placas"]:
            for f in self.carpetas[tipo].rglob("*.jpg"):
                try:
                    archivos.append((f.stat().st_mtime, f))
                except OSError:
                    pass

        # Ordenar por antigüedad (más viejo primero)
        archivos.sort(key=lambda x: x[0])

        # Calcular tamaño actual
        tamanio_actual = sum(
            self.carpetas[tipo].stat().st_size if self.carpetas[tipo].exists() else 0
            for tipo in ["personas", "vehiculos", "placas"]
        )
        tamanio_actual = self.espacio_usado_gb() * (1024 ** 3)

        eliminados = 0
        for _, archivo in archivos:
            if tamanio_actual <= max_bytes * 0.9:  # Mantener al 90% del límite
                break
            try:
                tamanio_archivo = archivo.stat().st_size
                archivo.unlink()
                tamanio_actual -= tamanio_archivo
                eliminados += 1

                # Eliminar también la entrada en DB
                nombre = archivo.stem
                BaseDatos.instancia().eliminar_evento_por_archivo(archivo.name)
            except OSError:
                pass

        if eliminados > 0:
            logging.getLogger("vigilancia").info(
                f"Auto-limpieza: {eliminados} archivos eliminados. "
                f"Espacio: {tamanio_actual / (1024**3):.2f} GB"
            )


# ══════════════════════════════════════════════════════════════════
# FASE 3: BASE DE DATOS SQLite OPTIMIZADA
# ══════════════════════════════════════════════════════════════════

class BaseDatos:
    """Base de datos SQLite con WAL mode para máxima concurrencia y velocidad."""
    _inst = None
    _lock = threading.Lock()

    @classmethod
    def instancia(cls):
        if cls._inst is None:
            with cls._lock:
                if cls._inst is None:
                    cls._inst = cls()
        return cls._inst

    def __init__(self):
        almacen = GestorAlmacenamiento()
        self.ruta_db = almacen.carpetas["db"] / "vigilancia.db"
        self._local = threading.local()
        self._inicializar_schema()

    def _conn(self) -> sqlite3.Connection:
        """Conexión thread-local con configuración optimizada."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self.ruta_db), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # Optimizaciones de rendimiento
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-32000")   # 32MB cache
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456") # 256MB mmap
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def _inicializar_schema(self):
        """Crea las tablas e índices optimizados."""
        conn = self._conn()
        conn.executescript("""
            -- Tabla principal de eventos de detección
            CREATE TABLE IF NOT EXISTS eventos (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL NOT NULL,           -- Unix timestamp con decimales
                fecha       TEXT NOT NULL,           -- YYYY-MM-DD
                hora        TEXT NOT NULL,           -- HH:MM:SS
                camara_id   INTEGER NOT NULL,
                camara_nom  TEXT NOT NULL,
                tipo        TEXT NOT NULL CHECK(tipo IN ('persona','vehiculo','placa')),
                confianza   REAL,                    -- 0.0 - 1.0
                descripcion TEXT,                    -- Descripción generada
                placa_texto TEXT,                    -- Texto de placa si aplica
                archivo_img TEXT,                    -- Nombre del archivo guardado
                bbox_x      INTEGER,                 -- Bounding box
                bbox_y      INTEGER,
                bbox_w      INTEGER,
                bbox_h      INTEGER,
                color_veh   TEXT,                    -- Color del vehículo si aplica
                tipo_veh    TEXT,                    -- Tipo: carro, moto, camión, etc.
                eliminado   INTEGER DEFAULT 0        -- Soft delete
            );

            -- Tabla de usuarios del sistema web
            CREATE TABLE IF NOT EXISTS usuarios (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                password_h  TEXT NOT NULL,           -- Bcrypt hash
                rol         TEXT DEFAULT 'viewer',   -- admin / viewer
                activo      INTEGER DEFAULT 1,
                creado      TEXT NOT NULL,
                ultimo_acc  TEXT,
                salt        TEXT NOT NULL
            );

            -- Tabla de sesiones web
            CREATE TABLE IF NOT EXISTS sesiones (
                token       TEXT PRIMARY KEY,
                usuario_id  INTEGER NOT NULL,
                creada      REAL NOT NULL,
                expira      REAL NOT NULL,
                ip_origen   TEXT,
                user_agent  TEXT,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
            );

            -- Tabla de intentos de login (para rate limiting)
            CREATE TABLE IF NOT EXISTS login_intentos (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                timestamp   REAL NOT NULL,
                exitoso     INTEGER DEFAULT 0
            );

            -- Tabla de IPs bloqueadas
            CREATE TABLE IF NOT EXISTS ips_bloqueadas (
                ip          TEXT PRIMARY KEY,
                hasta       REAL NOT NULL,
                razon       TEXT
            );

            -- Tabla de estadísticas por día
            CREATE TABLE IF NOT EXISTS estadisticas_dia (
                fecha       TEXT PRIMARY KEY,
                personas    INTEGER DEFAULT 0,
                vehiculos   INTEGER DEFAULT 0,
                placas      INTEGER DEFAULT 0,
                actualizado REAL
            );

            -- Tabla de configuración dinámica
            CREATE TABLE IF NOT EXISTS configuracion (
                clave       TEXT PRIMARY KEY,
                valor       TEXT NOT NULL,
                modificado  TEXT
            );

            -- ÍNDICES OPTIMIZADOS
            CREATE INDEX IF NOT EXISTS idx_eventos_timestamp ON eventos(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_eventos_fecha ON eventos(fecha, hora);
            CREATE INDEX IF NOT EXISTS idx_eventos_camara ON eventos(camara_id, tipo);
            CREATE INDEX IF NOT EXISTS idx_eventos_tipo ON eventos(tipo, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_eventos_placa ON eventos(placa_texto) WHERE placa_texto IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_sesiones_expira ON sesiones(expira);
            CREATE INDEX IF NOT EXISTS idx_login_ip ON login_intentos(ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eventos_no_eliminados ON eventos(eliminado, timestamp DESC);
        """)
        conn.commit()

        # Crear usuario admin por defecto si no existe
        self._crear_admin_default()

    def _crear_admin_default(self):
        """Crea el usuario admin con contraseña aleatoria segura si no existe."""
        conn = self._conn()
        existe = conn.execute("SELECT id FROM usuarios WHERE username='admin'").fetchone()
        if not existe:
            password = secrets.token_urlsafe(16)  # Contraseña aleatoria segura
            salt = secrets.token_hex(32)
            # Hash con PBKDF2 + SHA256 (más seguro que bcrypt simple)
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', password.encode(), salt.encode(), 600000
            ).hex()

            conn.execute("""
                INSERT INTO usuarios (username, password_h, rol, creado, salt)
                VALUES (?, ?, 'admin', ?, ?)
            """, ('admin', password_hash, datetime.now().isoformat(), salt))
            conn.commit()

            # Guardar credenciales en archivo para primera consulta
            creds_file = GestorAlmacenamiento().carpetas["sistema"] / "CREDENCIALES_INICIALES.txt"
            creds_file.write_text(
                f"===================================================\n"
                f"  CREDENCIALES DE ACCESO AL SISTEMA\n"
                f"  Generadas: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"===================================================\n"
                f"  Usuario:    admin\n"
                f"  Contrasena: {password}\n"
                f"===================================================\n"
                f"  CAMBIA LA CONTRASENA TRAS EL PRIMER ACCESO\n"
                f"  ELIMINA ESTE ARCHIVO DESPUES DE LEERLO\n"
                f"===================================================\n",
                encoding="utf-8"
            )
            print(f"\n  {'='*50}")
            print(f"  CREDENCIALES INICIALES GENERADAS:")
            print(f"  Usuario:    admin")
            print(f"  Contrasena: {password}")
            print(f"  Guardadas en: {creds_file}")
            print(f"  CAMBIA LA CONTRASENA EN EL PANEL WEB")
            print(f"  {'='*50}\n")

    def insertar_evento(self, datos: dict) -> int:
        """Inserta un evento de detección."""
        conn = self._conn()
        now = datetime.now()
        cur = conn.execute("""
            INSERT INTO eventos
            (timestamp, fecha, hora, camara_id, camara_nom, tipo, confianza,
             descripcion, placa_texto, archivo_img, bbox_x, bbox_y, bbox_w, bbox_h,
             color_veh, tipo_veh)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            now.timestamp(),
            now.strftime("%Y-%m-%d"),
            now.strftime("%H:%M:%S"),
            datos.get("camara_id"),
            datos.get("camara_nom"),
            datos.get("tipo"),
            datos.get("confianza"),
            datos.get("descripcion"),
            datos.get("placa_texto"),
            datos.get("archivo_img"),
            datos.get("bbox_x"), datos.get("bbox_y"),
            datos.get("bbox_w"), datos.get("bbox_h"),
            datos.get("color_veh"),
            datos.get("tipo_veh"),
        ))
        conn.commit()

        # Actualizar estadísticas del día
        self._actualizar_estadistica_dia(now.strftime("%Y-%m-%d"), datos.get("tipo"))
        return cur.lastrowid

    def _actualizar_estadistica_dia(self, fecha: str, tipo: str):
        conn = self._conn()
        col = {"persona": "personas", "vehiculo": "vehiculos", "placa": "placas"}.get(tipo, "personas")
        conn.execute(f"""
            INSERT INTO estadisticas_dia (fecha, {col}, actualizado)
            VALUES (?, 1, ?)
            ON CONFLICT(fecha) DO UPDATE SET
                {col} = {col} + 1,
                actualizado = excluded.actualizado
        """, (fecha, time.time()))
        conn.commit()

    def eliminar_evento_por_archivo(self, nombre_archivo: str):
        conn = self._conn()
        conn.execute("UPDATE eventos SET eliminado=1 WHERE archivo_img=?", (nombre_archivo,))
        conn.commit()

    def obtener_eventos(self, filtros: dict = None, limite: int = 100, offset: int = 0) -> list:
        """Obtiene eventos con filtros opcionales."""
        conn = self._conn()
        where = ["eliminado=0"]
        params = []

        if filtros:
            if filtros.get("tipo"):
                where.append("tipo=?")
                params.append(filtros["tipo"])
            if filtros.get("camara_id"):
                where.append("camara_id=?")
                params.append(filtros["camara_id"])
            if filtros.get("fecha_desde"):
                where.append("fecha >= ?")
                params.append(filtros["fecha_desde"])
            if filtros.get("fecha_hasta"):
                where.append("fecha <= ?")
                params.append(filtros["fecha_hasta"])
            if filtros.get("placa"):
                where.append("placa_texto LIKE ?")
                params.append(f"%{filtros['placa']}%")

        sql = f"""
            SELECT * FROM eventos
            WHERE {' AND '.join(where)}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params += [limite, offset]
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def obtener_estadisticas(self) -> dict:
        """Estadísticas generales del sistema."""
        conn = self._conn()
        hoy = datetime.now().strftime("%Y-%m-%d")
        ayer = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        total = dict(conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(tipo='persona') as personas,
                SUM(tipo='vehiculo') as vehiculos,
                SUM(tipo='placa') as placas
            FROM eventos WHERE eliminado=0
        """).fetchone())

        hoy_stats = conn.execute(
            "SELECT * FROM estadisticas_dia WHERE fecha=?", (hoy,)
        ).fetchone()
        hoy_dict = dict(hoy_stats) if hoy_stats else {"personas": 0, "vehiculos": 0, "placas": 0}

        return {"total": total, "hoy": hoy_dict}

    def verificar_usuario(self, username: str, password: str) -> Optional[dict]:
        """Verifica credenciales. Retorna usuario o None."""
        conn = self._conn()
        user = conn.execute(
            "SELECT * FROM usuarios WHERE username=? AND activo=1", (username,)
        ).fetchone()
        if not user:
            return None

        # Verificar contraseña con timing-safe comparison
        hash_calc = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), user['salt'].encode(), 600000
        ).hex()
        if hmac.compare_digest(hash_calc, user['password_h']):
            conn.execute(
                "UPDATE usuarios SET ultimo_acc=? WHERE id=?",
                (datetime.now().isoformat(), user['id'])
            )
            conn.commit()
            return dict(user)
        return None

    def cambiar_password(self, usuario_id: int, nueva_password: str) -> bool:
        conn = self._conn()
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', nueva_password.encode(), salt.encode(), 600000
        ).hex()
        conn.execute(
            "UPDATE usuarios SET password_h=?, salt=? WHERE id=?",
            (password_hash, salt, usuario_id)
        )
        conn.commit()
        return True

    def crear_sesion(self, usuario_id: int, ip: str, user_agent: str) -> str:
        """Crea una sesión segura y retorna el token."""
        conn = self._conn()
        token = secrets.token_urlsafe(64)
        ahora = time.time()
        expira = ahora + (CONFIG["sesion_timeout_min"] * 60)
        conn.execute("""
            INSERT INTO sesiones (token, usuario_id, creada, expira, ip_origen, user_agent)
            VALUES (?,?,?,?,?,?)
        """, (token, usuario_id, ahora, expira, ip, user_agent[:200]))
        conn.commit()
        return token

    def verificar_sesion(self, token: str) -> Optional[dict]:
        """Verifica si una sesión es válida."""
        if not token:
            return None
        conn = self._conn()
        sesion = conn.execute("""
            SELECT s.*, u.username, u.rol
            FROM sesiones s
            JOIN usuarios u ON s.usuario_id = u.id
            WHERE s.token=? AND s.expira > ?
        """, (token, time.time())).fetchone()

        if sesion:
            # Extender sesión
            nueva_expira = time.time() + (CONFIG["sesion_timeout_min"] * 60)
            conn.execute("UPDATE sesiones SET expira=? WHERE token=?", (nueva_expira, token))
            conn.commit()
            return dict(sesion)
        return None

    def cerrar_sesion(self, token: str):
        conn = self._conn()
        conn.execute("DELETE FROM sesiones WHERE token=?", (token,))
        conn.commit()

    def es_ip_bloqueada(self, ip: str) -> bool:
        conn = self._conn()
        row = conn.execute(
            "SELECT hasta FROM ips_bloqueadas WHERE ip=? AND hasta > ?",
            (ip, time.time())
        ).fetchone()
        return row is not None

    def registrar_intento_login(self, ip: str, exitoso: bool):
        conn = self._conn()
        conn.execute(
            "INSERT INTO login_intentos (ip, timestamp, exitoso) VALUES (?,?,?)",
            (ip, time.time(), 1 if exitoso else 0)
        )

        if not exitoso:
            # Contar fallos recientes (últimos 10 minutos)
            ventana = time.time() - 600
            fallos = conn.execute(
                "SELECT COUNT(*) FROM login_intentos WHERE ip=? AND timestamp>? AND exitoso=0",
                (ip, ventana)
            ).fetchone()[0]

            if fallos >= CONFIG["max_intentos_login"]:
                hasta = time.time() + (CONFIG["bloqueo_min"] * 60)
                conn.execute("""
                    INSERT INTO ips_bloqueadas (ip, hasta, razon) VALUES (?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET hasta=excluded.hasta
                """, (ip, hasta, f"{fallos} intentos fallidos"))

        conn.commit()

    def limpiar_sesiones_expiradas(self):
        conn = self._conn()
        conn.execute("DELETE FROM sesiones WHERE expira < ?", (time.time(),))
        conn.execute(
            "DELETE FROM login_intentos WHERE timestamp < ?",
            (time.time() - 86400,)  # Eliminar registros > 24h
        )
        conn.commit()

    def crear_usuario(self, username: str, password: str, rol: str = "viewer") -> bool:
        try:
            conn = self._conn()
            salt = secrets.token_hex(32)
            password_hash = hashlib.pbkdf2_hmac(
                'sha256', password.encode(), salt.encode(), 600000
            ).hex()
            conn.execute("""
                INSERT INTO usuarios (username, password_h, rol, creado, salt)
                VALUES (?,?,?,?,?)
            """, (username, password_hash, rol, datetime.now().isoformat(), salt))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def obtener_usuarios(self) -> list:
        conn = self._conn()
        return [dict(r) for r in conn.execute(
            "SELECT id, username, rol, activo, creado, ultimo_acc FROM usuarios"
        ).fetchall()]


# ══════════════════════════════════════════════════════════════════
# FASE 4: MOTOR DE DETECCIÓN
# ══════════════════════════════════════════════════════════════════

# Colores para descripción de vehículos
COLORES_BGR = {
    "blanco":  ([200, 200, 200], [255, 255, 255]),
    "negro":   ([0, 0, 0],       [60, 60, 60]),
    "gris":    ([60, 60, 60],    [200, 200, 200]),
    "rojo":    ([0, 0, 150],     [80, 80, 255]),
    "azul":    ([150, 0, 0],     [255, 80, 80]),
    "verde":   ([0, 150, 0],     [80, 255, 80]),
    "amarillo":([0, 200, 200],   [80, 255, 255]),
    "plateado":([150, 150, 150], [220, 220, 220]),
}

CLASES_VEHICULO = {
    2: "automóvil", 3: "motocicleta", 5: "autobús",
    6: "tren", 7: "camión", 8: "bote"
}

class MotorDeteccion:
    """Motor principal de detección usando YOLO + OpenCV + OCR."""

    def __init__(self):
        self.log = logging.getLogger("vigilancia.detector")
        self.modelo_yolo = None
        self.modelo_cara = None
        self.lector_ocr = None
        self._cargar_modelos()

    def _cargar_modelos(self):
        """Carga los modelos de IA disponibles."""
        print("  Cargando modelos de detección...")

        # YOLO para vehículos y personas. Por privacidad, solo carga modelos locales.
        if YOLO_DISPONIBLE:
            try:
                modelo_dir = Path(__file__).parent / "modelos"
                posibles = [
                    modelo_dir / "yolov8n.pt",
                    Path(__file__).parent / "yolov8n.pt",
                    Path.cwd() / "yolov8n.pt",
                ]
                modelo_local = next((m for m in posibles if m.exists()), None)
                if modelo_local is None and CONFIG.get("permitir_descargas_modelos", False):
                    # Puede descargar desde internet si no existe localmente.
                    self.modelo_yolo = YOLO("yolov8n.pt")
                elif modelo_local is not None:
                    self.modelo_yolo = YOLO(str(modelo_local))
                else:
                    self.modelo_yolo = None
                    print("  ⚠ YOLO desactivado: falta modelos/yolov8n.pt local")
                if self.modelo_yolo is not None:
                    print("  ✓ YOLOv8 cargado (personas + vehículos)")
            except Exception as e:
                self.log.warning(f"YOLO no disponible: {e}")

        # Detector de caras con DNN de OpenCV (más preciso que Haar)
        try:
            # Intentar usar el modelo DNN de OpenCV
            modelo_dir = Path(__file__).parent / "modelos"
            modelo_dir.mkdir(exist_ok=True)

            prototxt = modelo_dir / "deploy.prototxt"
            caffemodel = modelo_dir / "res10_300x300_ssd_iter_140000.caffemodel"

            # Por privacidad, no descargar modelos automáticamente salvo que se permita en CONFIG.
            if (not caffemodel.exists() or not prototxt.exists()) and CONFIG.get("permitir_descargas_modelos", False):
                self._descargar_modelo_cara(str(prototxt), str(caffemodel))

            if caffemodel.exists() and prototxt.exists():
                self.modelo_cara = cv2.dnn.readNetFromCaffe(str(prototxt), str(caffemodel))
                print("  ✓ Detector de caras DNN cargado")
            else:
                # Fallback a Haar cascade
                cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
                self.modelo_cara = cv2.CascadeClassifier(cascade_path)
                print("  ✓ Detector de caras Haar cargado (modo básico)")
        except Exception as e:
            self.log.warning(f"Detector de caras no disponible: {e}")
            # Usar Haar cascade como fallback
            try:
                cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
                self.modelo_cara = cv2.CascadeClassifier(cascade_path)
                print("  ✓ Detector de caras Haar cargado")
            except Exception as e2:
                self.log.error(f"No se pudo cargar detector de caras: {e2}")

        # OCR para placas
        if OCR_DISPONIBLE:
            try:
                self.lector_ocr = easyocr.Reader(['es', 'en'], gpu=False, verbose=False, download_enabled=bool(CONFIG.get('permitir_descargas_modelos', False)))
                print("  ✓ OCR para placas cargado")
            except Exception as e:
                self.log.warning(f"OCR no disponible: {e}")

        print("  ✓ Modelos cargados\n")

    def _descargar_modelo_cara(self, prototxt_path: str, caffemodel_path: str):
        """Descarga el modelo DNN de cara de OpenCV."""
        try:
            import urllib.request
            urls = {
                prototxt_path: "https://raw.githubusercontent.com/opencv/opencv/master/samples/dnn/face_detector/deploy.prototxt",
                caffemodel_path: "https://github.com/opencv/opencv_3rdparty/raw/dnn_samples_face_detector_20180205_fp16/res10_300x300_ssd_iter_140000_fp16.caffemodel"
            }
            for path, url in urls.items():
                if not Path(path).exists():
                    print(f"  Descargando modelo: {Path(path).name}...")
                    urllib.request.urlretrieve(url, path)
        except Exception as e:
            self.log.warning(f"No se pudo descargar modelo DNN: {e}")

    def detectar_caras(self, frame: np.ndarray) -> list:
        """Detecta caras en el frame. Retorna lista de (x,y,w,h,confianza)."""
        detecciones = []

        if self.modelo_cara is None:
            return detecciones

        try:
            if isinstance(self.modelo_cara, cv2.dnn.Net):
                # Modo DNN (más preciso)
                h, w = frame.shape[:2]
                blob = cv2.dnn.blobFromImage(
                    cv2.resize(frame, (300, 300)), 1.0,
                    (300, 300), (104.0, 177.0, 123.0)
                )
                self.modelo_cara.setInput(blob)
                detecs = self.modelo_cara.forward()

                for i in range(detecs.shape[2]):
                    confianza = float(detecs[0, 0, i, 2])
                    if confianza > CONFIG["confianza_cara"]:
                        box = detecs[0, 0, i, 3:7] * np.array([w, h, w, h])
                        x1, y1, x2, y2 = box.astype(int)
                        detecciones.append((
                            max(0, x1), max(0, y1),
                            min(w, x2-x1), min(h, y2-y1),
                            confianza
                        ))
            else:
                # Modo Haar (más rápido pero menos preciso)
                gris = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                caras = self.modelo_cara.detectMultiScale(
                    gris, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
                )
                for (x, y, w, h) in caras:
                    detecciones.append((x, y, w, h, 0.75))
        except Exception as e:
            self.log.debug(f"Error detectando caras: {e}")

        return detecciones

    def detectar_vehiculos_personas_yolo(self, frame: np.ndarray) -> dict:
        """Usa YOLO para detectar personas y vehículos."""
        resultado = {"personas": [], "vehiculos": []}

        if self.modelo_yolo is None:
            return resultado

        try:
            results = self.modelo_yolo(frame, verbose=False, conf=0.4)
            for r in results:
                for box in r.boxes:
                    cls_id = int(box.cls[0])
                    conf = float(box.conf[0])
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    bbox = (x1, y1, x2-x1, y2-y1, conf)

                    if cls_id == 0:  # Persona
                        resultado["personas"].append(bbox)
                    elif cls_id in CLASES_VEHICULO:
                        resultado["vehiculos"].append({
                            "bbox": bbox,
                            "tipo": CLASES_VEHICULO[cls_id]
                        })
        except Exception as e:
            self.log.debug(f"Error YOLO: {e}")

        return resultado

    def detectar_placa(self, frame: np.ndarray, bbox_vehiculo: tuple) -> Optional[str]:
        """Intenta leer la placa de un vehículo."""
        if self.lector_ocr is None:
            return None

        try:
            x, y, w, h = bbox_vehiculo[:4]
            # Región inferior del vehículo donde suele estar la placa
            y_placa = y + int(h * 0.6)
            h_placa = int(h * 0.4)
            roi = frame[y_placa:y_placa+h_placa, x:x+w]

            if roi.size == 0:
                return None

            # Preprocesar para OCR
            roi_gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
            roi_gray = cv2.bilateralFilter(roi_gray, 11, 17, 17)
            _, roi_bin = cv2.threshold(roi_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

            resultados = self.lector_ocr.readtext(roi_bin, allowlist='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-')

            for (bbox, texto, conf) in resultados:
                texto_limpio = re.sub(r'[^A-Z0-9]', '', texto.upper())
                if len(texto_limpio) >= 4 and conf >= CONFIG["confianza_placa"]:
                    return texto_limpio

        except Exception as e:
            self.log.debug(f"Error OCR placa: {e}")

        return None

    def detectar_color_vehiculo(self, frame: np.ndarray, bbox: tuple) -> str:
        """Detecta el color predominante de un vehículo."""
        try:
            x, y, w, h = bbox[:4]
            # Usar zona central del vehículo
            margen_x = int(w * 0.2)
            margen_y = int(h * 0.2)
            roi = frame[y+margen_y:y+h-margen_y, x+margen_x:x+w-margen_x]

            if roi.size == 0:
                return "desconocido"

            # Color promedio
            color_promedio = roi.mean(axis=(0, 1))

            # Clasificar color
            min_dist = float('inf')
            color_detectado = "desconocido"

            for nombre, (lower, upper) in COLORES_BGR.items():
                centro = [(l + u) / 2 for l, u in zip(lower, upper)]
                dist = sum((a-b)**2 for a, b in zip(color_promedio, centro)) ** 0.5
                if dist < min_dist:
                    min_dist = dist
                    color_detectado = nombre

            return color_detectado
        except Exception:
            return "desconocido"

    def procesar_frame(self, frame: np.ndarray, config_cam: dict) -> list:
        """
        Procesa un frame completo y retorna lista de detecciones.
        Cada detección: {'tipo', 'bbox', 'confianza', 'descripcion', ...}
        """
        detecciones = []
        h_frame, w_frame = frame.shape[:2]

        # ── Personas y Vehículos con YOLO ─────────────────────────
        if self.modelo_yolo and (config_cam["guardar_personas"] or config_cam["guardar_vehiculos"]):
            yolo_result = self.detectar_vehiculos_personas_yolo(frame)

            if config_cam["guardar_personas"]:
                for bbox in yolo_result["personas"]:
                    x, y, w, h, conf = bbox
                    det = {
                        "tipo": "persona",
                        "bbox": (x, y, w, h),
                        "confianza": conf,
                        "descripcion": f"Persona detectada — confianza {conf:.0%}",
                    }
                    detecciones.append(det)

            if config_cam["guardar_vehiculos"]:
                for veh in yolo_result["vehiculos"]:
                    bbox = veh["bbox"]
                    x, y, w, h, conf = bbox
                    color = self.detectar_color_vehiculo(frame, (x, y, w, h))
                    placa = None
                    if config_cam["guardar_placas"]:
                        placa = self.detectar_placa(frame, (x, y, w, h))

                    desc = f"{veh['tipo'].capitalize()} {color}"
                    if placa:
                        desc += f" — Placa: {placa}"

                    det = {
                        "tipo": "vehiculo",
                        "bbox": (x, y, w, h),
                        "confianza": conf,
                        "descripcion": desc,
                        "tipo_veh": veh["tipo"],
                        "color_veh": color,
                        "placa_texto": placa,
                    }
                    detecciones.append(det)

                    # Agregar detección de placa separada si se encontró
                    if placa and config_cam["guardar_placas"]:
                        detecciones.append({
                            "tipo": "placa",
                            "bbox": (x, y, w, h),
                            "confianza": conf,
                            "descripcion": f"Placa detectada: {placa} en {veh['tipo']} {color}",
                            "placa_texto": placa,
                            "tipo_veh": veh["tipo"],
                            "color_veh": color,
                        })

        # ── Caras (si YOLO no detectó personas o como complemento) ─
        elif config_cam["guardar_personas"]:
            caras = self.detectar_caras(frame)
            for x, y, w, h, conf in caras:
                detecciones.append({
                    "tipo": "persona",
                    "bbox": (x, y, w, h),
                    "confianza": conf,
                    "descripcion": f"Persona/cara detectada — confianza {conf:.0%}",
                })

        # Si YOLO está disponible pero no detectó personas, intentar cara también
        elif self.modelo_yolo and config_cam["guardar_personas"]:
            caras = self.detectar_caras(frame)
            for x, y, w, h, conf in caras:
                detecciones.append({
                    "tipo": "persona",
                    "bbox": (x, y, w, h),
                    "confianza": conf,
                    "descripcion": f"Cara detectada — confianza {conf:.0%}",
                })

        return detecciones

    def guardar_imagen_deteccion(
        self, frame: np.ndarray, bbox: tuple,
        tipo: str, camara_nom: str,
        almacen: GestorAlmacenamiento
    ) -> Optional[str]:
        """Guarda el recorte de la detección en disco."""
        try:
            x, y, w, h = bbox
            # Añadir margen
            margen = int(max(w, h) * 0.2)
            x1 = max(0, x - margen)
            y1 = max(0, y - margen)
            x2 = min(frame.shape[1], x + w + margen)
            y2 = min(frame.shape[0], y + h + margen)

            recorte = frame[y1:y2, x1:x2]
            if recorte.size == 0:
                return None

            ahora = datetime.now()
            nombre = f"{ahora.strftime('%Y%m%d_%H%M%S_%f')}.jpg"
            tipo_carpeta = {
                "persona": "personas",
                "vehiculo": "vehiculos",
                "placa": "placas"
            }.get(tipo, "personas")

            ruta = almacen.carpetas[tipo_carpeta] / camara_nom / nombre

            # Guardar con calidad configurada
            encode_params = [cv2.IMWRITE_JPEG_QUALITY, CONFIG["imagen_calidad"]]
            cv2.imwrite(str(ruta), recorte, encode_params)

            return nombre
        except Exception as e:
            logging.getLogger("vigilancia").error(f"Error guardando imagen: {e}")
            return None


# ══════════════════════════════════════════════════════════════════
# FASE 5: GESTOR DE CÁMARAS
# ══════════════════════════════════════════════════════════════════

class GestorCamara:
    """Maneja la conexión y procesamiento de una cámara RTSP individual."""

    def __init__(self, config_cam: dict, motor: MotorDeteccion, almacen: GestorAlmacenamiento):
        self.config = config_cam
        self.motor = motor
        self.almacen = almacen
        self.log = logging.getLogger(f"vigilancia.cam{config_cam['id']}")
        self.cap = None
        self.corriendo = False
        self.thread = None
        self.ultimo_guardado: Dict[str, float] = {}  # tipo -> timestamp
        self.stats = {"frames": 0, "detecciones": 0, "errores": 0}
        self.estado = "detenida"

    def conectar(self) -> bool:
        """Conecta a la cámara RTSP."""
        try:
            # Opciones de OpenCV para RTSP
            os.environ['OPENCV_FFMPEG_CAPTURE_OPTIONS'] = 'rtsp_transport;tcp|stimeout;5000000'
            self.cap = cv2.VideoCapture(self.config["url"], cv2.CAP_FFMPEG)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            self.cap.set(cv2.CAP_PROP_FPS, CONFIG["fps_proceso"])
            # Timeout de reconexión
            self.cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 10000)
            self.cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 5000)

            if self.cap.isOpened():
                self.log.info(f"Cámara {self.config['nombre']} conectada: {self.config['url']}")
                self.estado = "conectada"
                return True
            else:
                self.log.warning(f"No se pudo conectar a {self.config['url']}")
                self.estado = "error"
                return False
        except Exception as e:
            self.log.error(f"Error conectando cámara {self.config['id']}: {e}")
            self.estado = "error"
            return False

    def _puede_guardar(self, tipo: str) -> bool:
        """Verifica si se debe guardar (throttle por tipo)."""
        ahora = time.time()
        ultimo = self.ultimo_guardado.get(tipo, 0)
        if ahora - ultimo >= CONFIG["guardar_cada_seg"]:
            self.ultimo_guardado[tipo] = ahora
            return True
        return False

    def _procesar_loop(self):
        """Loop principal de captura y procesamiento."""
        fps_objetivo = CONFIG["fps_proceso"]
        intervalo = 1.0 / fps_objetivo
        ultimo_frame = 0
        errores_consecutivos = 0

        while self.corriendo:
            try:
                ahora = time.time()

                # Control de FPS para no saturar CPU
                if ahora - ultimo_frame < intervalo:
                    time.sleep(0.01)
                    continue

                if self.cap is None or not self.cap.isOpened():
                    self.estado = "reconectando"
                    time.sleep(5)
                    self.conectar()
                    continue

                ret, frame = self.cap.read()
                if not ret or frame is None:
                    errores_consecutivos += 1
                    if errores_consecutivos > 10:
                        self.log.warning("Muchos errores de lectura, reconectando...")
                        self.cap.release()
                        time.sleep(3)
                        self.conectar()
                        errores_consecutivos = 0
                    continue

                errores_consecutivos = 0
                ultimo_frame = time.time()
                self.stats["frames"] += 1

                # Procesar solo cada N frames
                if self.stats["frames"] % max(1, int(25 / fps_objetivo)) != 0:
                    continue

                # Reducir resolución para procesamiento (más rápido)
                frame_proc = cv2.resize(frame, (640, 360))

                # Detección
                detecciones = self.motor.procesar_frame(frame_proc, self.config)

                if not detecciones:
                    # Sin detección, continuar sin guardar nada
                    continue

                # Procesar y guardar detecciones
                for det in detecciones:
                    tipo = det["tipo"]

                    # Verificar si esta cámara debe guardar este tipo
                    if tipo == "persona" and not self.config["guardar_personas"]:
                        continue
                    if tipo == "vehiculo" and not self.config["guardar_vehiculos"]:
                        continue
                    if tipo == "placa" and not self.config["guardar_placas"]:
                        continue

                    # Throttle para no guardar duplicados inmediatos
                    if not self._puede_guardar(tipo):
                        continue

                    # Escalar bbox de vuelta al frame original
                    sx = frame.shape[1] / frame_proc.shape[1]
                    sy = frame.shape[0] / frame_proc.shape[0]
                    x, y, w, h = det["bbox"]
                    bbox_orig = (int(x*sx), int(y*sy), int(w*sx), int(h*sy))

                    # Guardar imagen
                    nombre_img = self.motor.guardar_imagen_deteccion(
                        frame, bbox_orig, tipo,
                        self.config["nombre"], self.almacen
                    )

                    # Insertar en base de datos
                    datos_evento = {
                        "camara_id": self.config["id"],
                        "camara_nom": self.config["nombre"],
                        "tipo": tipo,
                        "confianza": det.get("confianza"),
                        "descripcion": det.get("descripcion"),
                        "placa_texto": det.get("placa_texto"),
                        "archivo_img": nombre_img,
                        "bbox_x": bbox_orig[0], "bbox_y": bbox_orig[1],
                        "bbox_w": bbox_orig[2], "bbox_h": bbox_orig[3],
                        "color_veh": det.get("color_veh"),
                        "tipo_veh": det.get("tipo_veh"),
                    }
                    BaseDatos.instancia().insertar_evento(datos_evento)
                    self.stats["detecciones"] += 1

            except Exception as e:
                self.stats["errores"] += 1
                self.log.error(f"Error en loop de cámara {self.config['id']}: {e}")
                time.sleep(1)

    def iniciar(self):
        """Inicia el thread de la cámara."""
        if not self.config.get("activa", True):
            self.log.info(f"Cámara {self.config['nombre']} desactivada en config")
            return

        self.corriendo = True
        self.thread = threading.Thread(
            target=self._procesar_loop,
            name=f"cam_{self.config['id']}",
            daemon=True
        )
        self.thread.start()
        self.log.info(f"Cámara {self.config['nombre']} iniciada")

    def detener(self):
        """Detiene la cámara limpiamente."""
        self.corriendo = False
        if self.cap:
            self.cap.release()
        if self.thread:
            self.thread.join(timeout=5)
        self.estado = "detenida"


# ══════════════════════════════════════════════════════════════════
# FASE 6: SERVIDOR WEB SEGURO
# ══════════════════════════════════════════════════════════════════

# ── Template HTML del panel ──────────────────────────────────────
HTML_PANEL = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>Sistema de Vigilancia</title>
<meta name="robots" content="noindex, nofollow">
<style>
:root {
  --bg: #0a0a0f;
  --surface: #12121a;
  --surface2: #1a1a28;
  --border: #2a2a3d;
  --accent: #00d4ff;
  --accent2: #7c3aed;
  --danger: #ff4444;
  --warning: #ffaa00;
  --success: #00cc66;
  --text: #e0e0f0;
  --text-dim: #8888aa;
  --font: 'Courier New', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }

/* Login */
.login-wrap {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: radial-gradient(ellipse at center, #12122a 0%, #0a0a0f 70%);
}
.login-box {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 40px; width: 380px;
  box-shadow: 0 0 40px rgba(0,212,255,0.1);
}
.login-logo { text-align: center; margin-bottom: 30px; }
.login-logo h1 { font-size: 1.2em; color: var(--accent); letter-spacing: 3px; }
.login-logo p { color: var(--text-dim); font-size: 0.75em; margin-top: 5px; }
.login-box label { display: block; color: var(--text-dim); font-size: 0.75em; margin-bottom: 6px; letter-spacing: 1px; }
.login-box input {
  width: 100%; background: var(--bg); border: 1px solid var(--border);
  color: var(--text); padding: 12px; border-radius: 6px; font-family: var(--font);
  font-size: 0.9em; margin-bottom: 16px; outline: none; transition: border 0.2s;
}
.login-box input:focus { border-color: var(--accent); }
.btn {
  width: 100%; background: linear-gradient(135deg, var(--accent2), var(--accent));
  color: white; border: none; padding: 12px; border-radius: 6px;
  cursor: pointer; font-family: var(--font); font-size: 0.9em;
  letter-spacing: 2px; transition: opacity 0.2s;
}
.btn:hover { opacity: 0.85; }
.btn-sm {
  width: auto; padding: 6px 14px; font-size: 0.8em;
  border-radius: 4px; letter-spacing: 1px;
}
.error-msg { color: var(--danger); font-size: 0.8em; margin-bottom: 12px; text-align: center; }
.captcha-wrap { margin: 12px 0; }
.captcha-question { color: var(--accent); font-size: 0.85em; margin-bottom: 8px; }

/* Panel principal */
.header {
  background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 12px 24px; display: flex; align-items: center; justify-content: space-between;
}
.header h1 { font-size: 0.9em; color: var(--accent); letter-spacing: 2px; }
.header-right { display: flex; align-items: center; gap: 16px; font-size: 0.8em; }
.status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 5px; }
.dot-green { background: var(--success); box-shadow: 0 0 6px var(--success); animation: pulse 2s infinite; }
.dot-red { background: var(--danger); }
.dot-yellow { background: var(--warning); }

.layout { display: flex; height: calc(100vh - 50px); }
.sidebar {
  width: 220px; background: var(--surface); border-right: 1px solid var(--border);
  padding: 16px 0; flex-shrink: 0;
}
.sidebar a {
  display: flex; align-items: center; gap: 10px; padding: 10px 20px;
  color: var(--text-dim); text-decoration: none; font-size: 0.85em;
  transition: all 0.2s; border-left: 2px solid transparent;
}
.sidebar a:hover, .sidebar a.active {
  color: var(--accent); border-left-color: var(--accent); background: rgba(0,212,255,0.05);
}
.sidebar .section-title { color: var(--text-dim); font-size: 0.7em; padding: 16px 20px 6px; letter-spacing: 2px; }

.main { flex: 1; overflow-y: auto; padding: 24px; }
.page { display: none; }
.page.active { display: block; }

.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 20px; margin-bottom: 16px;
}
.card-title { color: var(--accent); font-size: 0.8em; letter-spacing: 2px; margin-bottom: 16px; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
.stat-card {
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; text-align: center;
}
.stat-num { font-size: 2em; font-weight: bold; color: var(--accent); }
.stat-label { color: var(--text-dim); font-size: 0.75em; margin-top: 4px; letter-spacing: 1px; }

.cameras-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.cam-card {
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: 8px; overflow: hidden;
}
.cam-header { padding: 10px 14px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--border); }
.cam-name { font-size: 0.85em; }
.cam-preview { background: #000; height: 160px; display: flex; align-items: center; justify-content: center; color: var(--text-dim); font-size: 0.8em; }
.cam-stats { padding: 8px 14px; font-size: 0.75em; color: var(--text-dim); display: flex; gap: 16px; }

.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.82em; }
th { color: var(--text-dim); text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 0.8em; letter-spacing: 1px; }
td { padding: 8px 12px; border-bottom: 1px solid rgba(42,42,61,0.5); vertical-align: middle; }
tr:hover td { background: rgba(0,212,255,0.03); }
.badge {
  padding: 2px 8px; border-radius: 3px; font-size: 0.75em;
  font-weight: bold; letter-spacing: 1px; display: inline-block;
}
.badge-persona { background: rgba(0,204,102,0.2); color: var(--success); border: 1px solid var(--success); }
.badge-vehiculo { background: rgba(0,212,255,0.2); color: var(--accent); border: 1px solid var(--accent); }
.badge-placa { background: rgba(255,170,0,0.2); color: var(--warning); border: 1px solid var(--warning); }

.filters { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; }
.filters select, .filters input {
  background: var(--surface2); border: 1px solid var(--border); color: var(--text);
  padding: 7px 12px; border-radius: 5px; font-family: var(--font); font-size: 0.82em;
}

.storage-bar { background: var(--bg); border-radius: 4px; height: 8px; margin: 8px 0; overflow: hidden; }
.storage-fill { height: 100%; border-radius: 4px; background: linear-gradient(90deg, var(--accent), var(--accent2)); transition: width 0.5s; }

@keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }

.form-row { margin-bottom: 14px; }
.form-row label { display: block; color: var(--text-dim); font-size: 0.78em; margin-bottom: 5px; letter-spacing: 1px; }
.form-row input, .form-row select {
  background: var(--surface2); border: 1px solid var(--border); color: var(--text);
  padding: 9px 12px; border-radius: 5px; font-family: var(--font); font-size: 0.85em; width: 100%;
}
.form-row input:focus { border-color: var(--accent); outline: none; }

.alert { padding: 10px 14px; border-radius: 5px; font-size: 0.82em; margin-bottom: 12px; }
.alert-success { background: rgba(0,204,102,0.1); border: 1px solid var(--success); color: var(--success); }
.alert-danger { background: rgba(255,68,68,0.1); border: 1px solid var(--danger); color: var(--danger); }
</style>
</head>
<body>

<!-- ═══════════════ LOGIN ═══════════════ -->
<div id="loginPage" class="login-wrap" style="display:{% if logged_in %}none{% else %}flex{% endif %}">
  <div class="login-box">
    <div class="login-logo">
      <h1>◉ VIGILANCIA</h1>
      <p>SISTEMA DE SEGURIDAD — ACCESO RESTRINGIDO</p>
    </div>
    {% if error %}<div class="error-msg">{{ error }}</div>{% endif %}
    <form method="POST" action="/login" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <div>
        <label>USUARIO</label>
        <input type="text" name="username" autocomplete="off" spellcheck="false" maxlength="50" required>
      </div>
      <div>
        <label>CONTRASEÑA</label>
        <input type="password" name="password" autocomplete="new-password" maxlength="128" required>
      </div>
      <div class="captcha-wrap">
        <label>VERIFICACIÓN</label>
        <div class="captcha-question">{{ captcha_pregunta }}</div>
        <input type="text" name="captcha" placeholder="Respuesta" maxlength="10" required>
        <input type="hidden" name="captcha_resp" value="{{ captcha_resp }}">
      </div>
      <button type="submit" class="btn">INGRESAR →</button>
    </form>
  </div>
</div>

<!-- ═══════════════ PANEL PRINCIPAL ═══════════════ -->
<div id="mainPanel" style="display:{% if logged_in %}block{% else %}none{% endif %}">
  <div class="header">
    <h1>◉ SISTEMA DE VIGILANCIA</h1>
    <div class="header-right">
      <span id="serverTime" style="color:var(--text-dim)"></span>
      <span><span class="status-dot dot-green"></span>ACTIVO</span>
      <span style="color:var(--text-dim)">{{ username }}</span>
      <a href="/logout" style="color:var(--danger);text-decoration:none;font-size:0.8em">SALIR</a>
    </div>
  </div>

  <div class="layout">
    <div class="sidebar">
      <div class="section-title">MENÚ</div>
      <a href="#" class="active" onclick="showPage('dashboard')">⬡ DASHBOARD</a>
      <a href="#" onclick="showPage('camaras')">◎ CÁMARAS</a>
      <a href="#" onclick="showPage('eventos')">☰ EVENTOS</a>
      <a href="#" onclick="showPage('buscar')">⌕ BUSCAR</a>
      <div class="section-title">SISTEMA</div>
      <a href="#" onclick="showPage('almacenamiento')">⊟ ALMACENAMIENTO</a>
      {% if rol == 'admin' %}
      <a href="#" onclick="showPage('usuarios')">◈ USUARIOS</a>
      <a href="#" onclick="showPage('config')">⚙ CONFIGURACIÓN</a>
      {% endif %}
      <a href="#" onclick="showPage('miCuenta')">◎ MI CUENTA</a>
    </div>

    <div class="main">

      <!-- DASHBOARD -->
      <div id="page-dashboard" class="page active">
        <div class="stats-grid" id="statsGrid"></div>
        <div class="card">
          <div class="card-title">ÚLTIMAS DETECCIONES</div>
          <div id="ultimasDetecciones"></div>
        </div>
        <div class="card">
          <div class="card-title">ACTIVIDAD HOY POR HORA</div>
          <div id="actividadHoy" style="color:var(--text-dim);font-size:0.82em">Cargando...</div>
        </div>
      </div>

      <!-- CÁMARAS -->
      <div id="page-camaras" class="page">
        <div class="card">
          <div class="card-title">ESTADO DE CÁMARAS</div>
          <div class="cameras-grid" id="camarasGrid"></div>
        </div>
      </div>

      <!-- EVENTOS -->
      <div id="page-eventos" class="page">
        <div class="card">
          <div class="card-title">REGISTRO DE EVENTOS</div>
          <div class="filters">
            <select id="filtroTipo" onchange="cargarEventos()">
              <option value="">Todos los tipos</option>
              <option value="persona">Personas</option>
              <option value="vehiculo">Vehículos</option>
              <option value="placa">Placas</option>
            </select>
            <select id="filtroCamara" onchange="cargarEventos()">
              <option value="">Todas las cámaras</option>
              {% for cam in camaras %}
              <option value="{{ cam.id }}">{{ cam.nombre }}</option>
              {% endfor %}
            </select>
            <input type="date" id="filtroDesde" onchange="cargarEventos()">
            <input type="date" id="filtroHasta" onchange="cargarEventos()">
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>HORA</th><th>CÁMARA</th><th>TIPO</th>
                  <th>DESCRIPCIÓN</th><th>PLACA</th><th>CONF.</th>
                </tr>
              </thead>
              <tbody id="eventosTabla"></tbody>
            </table>
          </div>
          <div id="eventosPaginacion" style="margin-top:12px;font-size:0.8em;color:var(--text-dim)"></div>
        </div>
      </div>

      <!-- BUSCAR -->
      <div id="page-buscar" class="page">
        <div class="card">
          <div class="card-title">BÚSQUEDA DE PLACAS</div>
          <div class="filters">
            <input type="text" id="buscarPlaca" placeholder="Ej: ABC123" style="width:200px">
            <button class="btn btn-sm" onclick="buscarPlaca()">BUSCAR</button>
          </div>
          <div id="resultadosBusqueda"></div>
        </div>
      </div>

      <!-- ALMACENAMIENTO -->
      <div id="page-almacenamiento" class="page">
        <div class="card">
          <div class="card-title">USO DE DISCO</div>
          <div id="storageInfo">Cargando...</div>
        </div>
      </div>

      <!-- USUARIOS (admin) -->
      <div id="page-usuarios" class="page">
        <div class="card">
          <div class="card-title">USUARIOS DEL SISTEMA</div>
          <div id="usuariosList"></div>
          <hr style="border-color:var(--border);margin:20px 0">
          <div class="card-title">CREAR USUARIO</div>
          <div class="form-row"><label>USUARIO</label><input type="text" id="nuevoUsername" maxlength="30"></div>
          <div class="form-row"><label>CONTRASEÑA</label><input type="password" id="nuevoPassword" maxlength="128"></div>
          <div class="form-row">
            <label>ROL</label>
            <select id="nuevoRol">
              <option value="viewer">Visor</option>
              <option value="admin">Administrador</option>
            </select>
          </div>
          <button class="btn btn-sm" onclick="crearUsuario()">CREAR USUARIO</button>
          <div id="usuarioMsg"></div>
        </div>
      </div>

      <!-- MI CUENTA -->
      <div id="page-miCuenta" class="page">
        <div class="card" style="max-width:400px">
          <div class="card-title">CAMBIAR CONTRASEÑA</div>
          <div class="form-row"><label>CONTRASEÑA ACTUAL</label><input type="password" id="passActual" maxlength="128"></div>
          <div class="form-row"><label>NUEVA CONTRASEÑA</label><input type="password" id="passNueva" maxlength="128"></div>
          <div class="form-row"><label>CONFIRMAR</label><input type="password" id="passConfirm" maxlength="128"></div>
          <button class="btn btn-sm" onclick="cambiarPassword()">CAMBIAR CONTRASEÑA</button>
          <div id="passMsg" style="margin-top:10px;font-size:0.82em"></div>
        </div>
      </div>

      <!-- CONFIG -->
      <div id="page-config" class="page">
        <div class="card">
          <div class="card-title">INFORMACIÓN DEL SISTEMA</div>
          <div id="configInfo" style="font-size:0.82em;color:var(--text-dim)">Cargando...</div>
        </div>
      </div>

    </div>
  </div>
</div>

<script>
const CSRF = document.querySelector('input[name="csrf_token"]')?.value || '';

// Reloj en tiempo real
function updateClock() {
  const el = document.getElementById('serverTime');
  if (el) {
    const now = new Date();
    el.textContent = now.toLocaleString('es-MX', {
      hour:'2-digit', minute:'2-digit', second:'2-digit',
      day:'2-digit', month:'2-digit', year:'numeric'
    });
  }
}
setInterval(updateClock, 1000);
updateClock();

// Navegación
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
  const page = document.getElementById('page-' + name);
  if (page) {
    page.classList.add('active');
    // Cargar datos al cambiar página
    if (name === 'dashboard') loadDashboard();
    if (name === 'eventos') cargarEventos();
    if (name === 'camaras') cargarCamaras();
    if (name === 'almacenamiento') cargarAlmacenamiento();
    if (name === 'usuarios') cargarUsuarios();
    if (name === 'config') cargarConfig();
  }
  event?.target?.classList.add('active');
}

async function api(url, opts = {}) {
  try {
    const r = await fetch(url, {
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
      credentials: 'same-origin',
      ...opts
    });
    if (r.status === 401) { window.location.href = '/login'; return null; }
    return await r.json();
  } catch (e) { console.error('API error:', e); return null; }
}

// ── Dashboard ──────────────────────────────────────────────────
async function loadDashboard() {
  const stats = await api('/api/stats');
  if (!stats) return;

  const grid = document.getElementById('statsGrid');
  grid.innerHTML = `
    <div class="stat-card">
      <div class="stat-num">${stats.total.personas || 0}</div>
      <div class="stat-label">PERSONAS TOTAL</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">${stats.total.vehiculos || 0}</div>
      <div class="stat-label">VEHÍCULOS TOTAL</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">${stats.total.placas || 0}</div>
      <div class="stat-label">PLACAS LEÍDAS</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">${stats.hoy.personas || 0}</div>
      <div class="stat-label">PERSONAS HOY</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">${stats.hoy.vehiculos || 0}</div>
      <div class="stat-label">VEHÍCULOS HOY</div>
    </div>
    <div class="stat-card">
      <div class="stat-num">${stats.espacio_gb?.toFixed(1) || '0.0'} GB</div>
      <div class="stat-label">ESPACIO USADO</div>
    </div>
  `;

  const eventos = await api('/api/eventos?limite=15');
  if (eventos) {
    const div = document.getElementById('ultimasDetecciones');
    div.innerHTML = renderTablaEventos(eventos.items || []);
  }
}

// ── Eventos ────────────────────────────────────────────────────
let eventosOffset = 0;
async function cargarEventos() {
  const tipo = document.getElementById('filtroTipo')?.value || '';
  const camara = document.getElementById('filtroCamara')?.value || '';
  const desde = document.getElementById('filtroDesde')?.value || '';
  const hasta = document.getElementById('filtroHasta')?.value || '';

  let url = `/api/eventos?limite=50&offset=${eventosOffset}`;
  if (tipo) url += `&tipo=${tipo}`;
  if (camara) url += `&camara_id=${camara}`;
  if (desde) url += `&fecha_desde=${desde}`;
  if (hasta) url += `&fecha_hasta=${hasta}`;

  const data = await api(url);
  if (!data) return;

  document.getElementById('eventosTabla').innerHTML = renderFilas(data.items || []);
  document.getElementById('eventosPaginacion').textContent =
    `Mostrando ${(data.items||[]).length} de ${data.total || 0} eventos`;
}

function renderTablaEventos(items) {
  return `<div class="table-wrap"><table>
    <thead><tr><th>HORA</th><th>CÁMARA</th><th>TIPO</th><th>DESCRIPCIÓN</th><th>PLACA</th></tr></thead>
    <tbody>${renderFilas(items)}</tbody>
  </table></div>`;
}

function renderFilas(items) {
  if (!items.length) return '<tr><td colspan="6" style="color:var(--text-dim);text-align:center;padding:20px">Sin detecciones</td></tr>';
  return items.map(e => `<tr>
    <td style="color:var(--text-dim)">${e.fecha} ${e.hora}</td>
    <td>${e.camara_nom}</td>
    <td><span class="badge badge-${e.tipo}">${e.tipo.toUpperCase()}</span></td>
    <td>${e.descripcion || '—'}</td>
    <td style="color:var(--warning);font-weight:bold">${e.placa_texto || '—'}</td>
    <td>${e.confianza ? (e.confianza*100).toFixed(0)+'%' : '—'}</td>
  </tr>`).join('');
}

// ── Búsqueda placa ─────────────────────────────────────────────
async function buscarPlaca() {
  const placa = document.getElementById('buscarPlaca').value.trim();
  if (!placa) return;
  const data = await api(`/api/eventos?placa=${encodeURIComponent(placa)}&limite=100`);
  const div = document.getElementById('resultadosBusqueda');
  if (data?.items?.length) {
    div.innerHTML = renderTablaEventos(data.items);
  } else {
    div.innerHTML = `<p style="color:var(--text-dim);padding:20px">No se encontró la placa: ${placa}</p>`;
  }
}

// ── Cámaras ────────────────────────────────────────────────────
async function cargarCamaras() {
  const data = await api('/api/camaras');
  if (!data) return;
  const grid = document.getElementById('camarasGrid');
  grid.innerHTML = (data.camaras || []).map(cam => `
    <div class="cam-card">
      <div class="cam-header">
        <span class="cam-name">${cam.nombre}</span>
        <span class="status-dot ${cam.estado === 'conectada' ? 'dot-green' : 'dot-red'}"></span>
      </div>
      <div class="cam-preview">
        <span>${cam.estado === 'conectada' ? '● EN VIVO' : '○ SIN SEÑAL'}</span>
      </div>
      <div class="cam-stats">
        <span>Frames: ${cam.stats?.frames || 0}</span>
        <span>Detecciones: ${cam.stats?.detecciones || 0}</span>
        <span>Errores: ${cam.stats?.errores || 0}</span>
      </div>
      <div style="padding:6px 14px;font-size:0.73em;color:var(--text-dim)">${cam.descripcion}</div>
    </div>
  `).join('');
}

// ── Almacenamiento ─────────────────────────────────────────────
async function cargarAlmacenamiento() {
  const data = await api('/api/almacenamiento');
  if (!data) return;
  const pct = Math.min(100, (data.usado_gb / data.max_gb) * 100);
  const color = pct > 85 ? 'var(--danger)' : pct > 60 ? 'var(--warning)' : 'var(--success)';
  document.getElementById('storageInfo').innerHTML = `
    <div style="margin-bottom:16px">
      <div style="display:flex;justify-content:space-between;font-size:0.82em;margin-bottom:6px">
        <span>Usado: ${data.usado_gb.toFixed(2)} GB</span>
        <span>Límite: ${data.max_gb} GB</span>
      </div>
      <div class="storage-bar"><div class="storage-fill" style="width:${pct}%;background:${color}"></div></div>
      <div style="color:var(--text-dim);font-size:0.78em;margin-top:4px">${pct.toFixed(1)}% utilizado</div>
    </div>
    <div style="font-size:0.82em;color:var(--text-dim)">
      <div>• Personas: ${data.personas_gb?.toFixed(2) || 0} GB</div>
      <div>• Vehículos: ${data.vehiculos_gb?.toFixed(2) || 0} GB</div>
      <div>• Placas: ${data.placas_gb?.toFixed(2) || 0} GB</div>
      <div style="margin-top:8px">Ruta: ${data.ruta}</div>
    </div>
  `;
}

// ── Usuarios ───────────────────────────────────────────────────
async function cargarUsuarios() {
  const data = await api('/api/usuarios');
  if (!data) return;
  document.getElementById('usuariosList').innerHTML = `
    <div class="table-wrap"><table>
      <thead><tr><th>USUARIO</th><th>ROL</th><th>ACTIVO</th><th>ÚLTIMO ACCESO</th></tr></thead>
      <tbody>${(data.usuarios || []).map(u => `
        <tr>
          <td>${u.username}</td>
          <td><span class="badge ${u.rol==='admin'?'badge-placa':'badge-vehiculo'}">${u.rol.toUpperCase()}</span></td>
          <td><span class="status-dot ${u.activo?'dot-green':'dot-red'}"></span></td>
          <td style="color:var(--text-dim)">${u.ultimo_acc || 'Nunca'}</td>
        </tr>
      `).join('')}</tbody>
    </table></div>
  `;
}

async function crearUsuario() {
  const username = document.getElementById('nuevoUsername').value.trim();
  const password = document.getElementById('nuevoPassword').value;
  const rol = document.getElementById('nuevoRol').value;
  if (!username || !password) return;

  const r = await api('/api/usuarios', {
    method: 'POST',
    body: JSON.stringify({ username, password, rol })
  });
  const msg = document.getElementById('usuarioMsg');
  if (r?.ok) {
    msg.innerHTML = '<div class="alert alert-success">Usuario creado exitosamente</div>';
    cargarUsuarios();
  } else {
    msg.innerHTML = `<div class="alert alert-danger">${r?.error || 'Error al crear usuario'}</div>`;
  }
}

// ── Mi cuenta ──────────────────────────────────────────────────
async function cambiarPassword() {
  const actual = document.getElementById('passActual').value;
  const nueva = document.getElementById('passNueva').value;
  const confirm = document.getElementById('passConfirm').value;
  const msg = document.getElementById('passMsg');

  if (nueva !== confirm) {
    msg.innerHTML = '<span style="color:var(--danger)">Las contraseñas no coinciden</span>';
    return;
  }
  if (nueva.length < 8) {
    msg.innerHTML = '<span style="color:var(--danger)">Mínimo 8 caracteres</span>';
    return;
  }

  const r = await api('/api/cambiar-password', {
    method: 'POST',
    body: JSON.stringify({ password_actual: actual, password_nueva: nueva })
  });

  if (r?.ok) {
    msg.innerHTML = '<span style="color:var(--success)">Contraseña actualizada</span>';
    document.getElementById('passActual').value = '';
    document.getElementById('passNueva').value = '';
    document.getElementById('passConfirm').value = '';
  } else {
    msg.innerHTML = `<span style="color:var(--danger)">${r?.error || 'Error'}</span>`;
  }
}

// ── Config info ────────────────────────────────────────────────
async function cargarConfig() {
  const data = await api('/api/sistema-info');
  if (!data) return;
  document.getElementById('configInfo').innerHTML = `
    <div>Python: ${data.python}</div>
    <div>OpenCV: ${data.opencv}</div>
    <div>YOLO disponible: ${data.yolo ? '✓' : '✗'}</div>
    <div>OCR disponible: ${data.ocr ? '✓' : '✗'}</div>
    <div>Cámaras activas: ${data.camaras_activas}</div>
    <div>Uptime: ${data.uptime}</div>
  `;
}

// Cargar dashboard al inicio
if (document.getElementById('mainPanel')?.style.display !== 'none') {
  loadDashboard();
  setInterval(loadDashboard, 30000);
  setInterval(cargarCamaras, 15000);
}
</script>
</body>
</html>
"""

class ServidorWeb:
    """Servidor Flask con seguridad completa."""

    def __init__(self, gestores_camara: list, almacen: GestorAlmacenamiento):
        self.app = Flask(__name__)
        # Clave secreta persistente: evita que las sesiones se rompan en cada reinicio.
        self.app.secret_key = self._cargar_o_crear_secret_key()
        cookie_secure = bool(CONFIG.get("web_ssl", False))
        self.app.config.update({
            # En HTTP local debe ser False, si no el navegador no guarda la cookie
            # y el login redirige al inicio. En HTTPS se activa automáticamente.
            "SESSION_COOKIE_SECURE": cookie_secure,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_NAME": "vs_session",
            "PERMANENT_SESSION_LIFETIME": timedelta(minutes=CONFIG["sesion_timeout_min"]),
            "MAX_CONTENT_LENGTH": 1 * 1024 * 1024,  # 1MB máximo
        })
        self.gestores = gestores_camara
        self.almacen = almacen
        self.inicio = datetime.now()
        self.csrf_tokens: Dict[str, float] = {}  # token -> expira
        self.csrf_lock = threading.Lock()
        self._registrar_rutas()

    def _cargar_o_crear_secret_key(self) -> bytes:
        """Carga una clave secreta local o la crea una sola vez. No sale a internet."""
        try:
            secret_dir = self.almacen.carpetas["sistema"]
            secret_dir.mkdir(parents=True, exist_ok=True)
            secret_file = secret_dir / "flask_secret.key"
            if secret_file.exists():
                data = secret_file.read_bytes()
                if len(data) >= 32:
                    return data
            data = secrets.token_bytes(64)
            secret_file.write_bytes(data)
            try:
                os.chmod(str(secret_file), 0o600)
            except Exception:
                pass
            return data
        except Exception:
            # Último recurso: funciona, pero las sesiones se cerrarán al reiniciar.
            return secrets.token_bytes(64)

    def _generar_csrf(self) -> str:
        token = secrets.token_urlsafe(32)
        with self.csrf_lock:
            self.csrf_tokens[token] = time.time() + 3600
            # Limpiar tokens viejos
            expirados = [t for t, exp in self.csrf_tokens.items() if exp < time.time()]
            for t in expirados:
                del self.csrf_tokens[t]
        return token

    def _validar_csrf(self, token: str) -> bool:
        with self.csrf_lock:
            exp = self.csrf_tokens.get(token)
            return exp is not None and exp > time.time()

    def _get_ip(self) -> str:
        """Obtiene IP real del cliente."""
        if request.headers.get("X-Forwarded-For"):
            return request.headers["X-Forwarded-For"].split(",")[0].strip()
        return request.remote_addr or "0.0.0.0"

    def _verificar_sesion(self):
        """Verifica sesión válida.

        Usa dos mecanismos compatibles:
        1) sesión firmada de Flask, para que el panel no rebote al login;
        2) token persistente en SQLite, para poder invalidar sesiones desde servidor.
        """
        token = request.cookies.get("vs_token")
        sesion_db = BaseDatos.instancia().verificar_sesion(token) if token else None
        if sesion_db:
            # Mantener también la sesión firmada sincronizada.
            session.permanent = True
            session["auth"] = True
            session["user_id"] = sesion_db.get("usuario_id")
            session["username"] = sesion_db.get("username", "")
            session["rol"] = sesion_db.get("rol", "viewer")
            return sesion_db

        # Fallback seguro: cookie firmada de Flask. Evita el bucle de redirección
        # si el navegador pierde la cookie personalizada pero conserva vs_session.
        if session.get("auth") and session.get("user_id"):
            return {
                "usuario_id": session.get("user_id"),
                "username": session.get("username", ""),
                "rol": session.get("rol", "viewer"),
            }
        return None

    def _capcha_simple(self) -> Tuple[str, int]:
        """Genera un captcha matemático simple."""
        a = secrets.randbelow(10) + 1
        b = secrets.randbelow(10) + 1
        ops = [
            (f"¿Cuánto es {a} + {b}?", a + b),
            (f"¿Cuánto es {a} × {b}?", a * b),
            (f"¿Cuánto es {a+b} - {a}?", b),
        ]
        return ops[secrets.randbelow(len(ops))]

    def _render_login(self, error: str = ""):
        pregunta, respuesta = self._capcha_simple()
        return render_template_string(
            HTML_PANEL, logged_in=False, error=error,
            csrf_token=self._generar_csrf(),
            captcha_pregunta=pregunta,
            captcha_resp=hashlib.sha256(str(respuesta).encode()).hexdigest(),
            username="", rol="", camaras=CONFIG["camaras"]
        )

    def _headers_seguridad(self, response):
        """Agrega headers de seguridad a todas las respuestas."""
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "base-uri 'self'; "
                "form-action 'self';"
            ),
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "Server": "",  # No revelar software
        }
        if CONFIG.get("web_ssl", False):
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers.update(headers)
        return response

    def _registrar_rutas(self):
        app = self.app

        @app.after_request
        def after_req(response):
            return self._headers_seguridad(response)

        @app.before_request
        def antes_req():
            # Si SSL está activo, aceptar solo HTTPS. Evita enviar cookies por HTTP.
            if CONFIG.get("web_ssl", False) and CONFIG.get("forzar_https", True) and not request.is_secure:
                # Permite que Flask sirva internamente; en acceso directo con ssl_context request.is_secure=True.
                return "HTTPS requerido. Usa https:// en la barra del navegador.", 403

            # Verificar IP bloqueada
            ip = self._get_ip()
            if request.path not in ["/login", "/favicon.ico"] and \
               BaseDatos.instancia().es_ip_bloqueada(ip):
                return "Acceso denegado temporalmente.", 403

        @app.route("/")
        def index():
            sesion = self._verificar_sesion()
            csrf = self._generar_csrf()
            pregunta, respuesta = self._capcha_simple()
            resp_hash = hashlib.sha256(str(respuesta).encode()).hexdigest()
            return render_template_string(
                HTML_PANEL,
                logged_in=bool(sesion),
                username=sesion.get("username", "") if sesion else "",
                rol=sesion.get("rol", "viewer") if sesion else "",
                csrf_token=csrf,
                captcha_pregunta=pregunta,
                captcha_resp=resp_hash,
                camaras=CONFIG["camaras"],
                error="",
            )

        @app.route("/login", methods=["POST"])
        def login():
            ip = self._get_ip()
            db = BaseDatos.instancia()

            # Rate limiting básico
            if db.es_ip_bloqueada(ip):
                return self._render_login("IP bloqueada temporalmente. Intenta más tarde.")

            # Validar CSRF
            csrf = request.form.get("csrf_token", "")
            if not self._validar_csrf(csrf):
                return self._render_login("Token inválido. Recarga la página.")

            # Validar captcha
            captcha_input = request.form.get("captcha", "").strip()
            captcha_resp = request.form.get("captcha_resp", "")
            captcha_hash = hashlib.sha256(captcha_input.encode()).hexdigest()
            if not hmac.compare_digest(captcha_hash, captcha_resp):
                db.registrar_intento_login(ip, False)
                pregunta, respuesta = self._capcha_simple()
                return render_template_string(
                    HTML_PANEL, logged_in=False,
                    error="Verificación incorrecta.",
                    csrf_token=self._generar_csrf(),
                    captcha_pregunta=pregunta,
                    captcha_resp=hashlib.sha256(str(respuesta).encode()).hexdigest(),
                    username="", rol="", camaras=CONFIG["camaras"]
                )

            # Validar credenciales
            username = request.form.get("username", "").strip()[:50]
            password = request.form.get("password", "")[:128]

            # Delay artificial anti-timing attack
            time.sleep(secrets.randbelow(3) * 0.1 + 0.2)

            usuario = db.verificar_usuario(username, password)
            if not usuario:
                db.registrar_intento_login(ip, False)
                pregunta, respuesta = self._capcha_simple()
                return render_template_string(
                    HTML_PANEL, logged_in=False,
                    error="Credenciales incorrectas.",
                    csrf_token=self._generar_csrf(),
                    captcha_pregunta=pregunta,
                    captcha_resp=hashlib.sha256(str(respuesta).encode()).hexdigest(),
                    username="", rol="", camaras=CONFIG["camaras"]
                )

            # Login exitoso
            db.registrar_intento_login(ip, True)
            token = db.crear_sesion(
                usuario["id"], ip,
                request.headers.get("User-Agent", "")[:200]
            )

            # Guardar sesión firmada de Flask + token de servidor.
            # Renderizamos el panel directamente en vez de redirigir, para evitar
            # el bucle de login cuando el navegador tarda en persistir cookies.
            session.clear()
            session.permanent = True
            session["auth"] = True
            session["user_id"] = usuario["id"]
            session["username"] = usuario["username"]
            session["rol"] = usuario.get("rol", "viewer")

            response = make_response(render_template_string(
                HTML_PANEL,
                logged_in=True,
                username=usuario["username"],
                rol=usuario.get("rol", "viewer"),
                csrf_token=self._generar_csrf(),
                captcha_pregunta="",
                captcha_resp="",
                camaras=CONFIG["camaras"],
                error="",
            ))
            response.set_cookie(
                "vs_token", token,
                httponly=True,
                secure=bool(CONFIG.get("web_ssl", False)),
                samesite="Lax",
                path="/",
                max_age=CONFIG["sesion_timeout_min"] * 60
            )
            return response

        @app.route("/logout")
        def logout():
            token = request.cookies.get("vs_token")
            if token:
                BaseDatos.instancia().cerrar_sesion(token)
            session.clear()
            response = redirect("/")
            response.delete_cookie("vs_token", path="/")
            return response

        # ── API Endpoints ──────────────────────────────────────────
        def require_auth(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                sesion = self._verificar_sesion()
                if not sesion:
                    return jsonify({"error": "No autorizado"}), 401
                return f(sesion, *args, **kwargs)
            return decorated

        def require_admin(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                sesion = self._verificar_sesion()
                if not sesion:
                    return jsonify({"error": "No autorizado"}), 401
                if sesion.get("rol") != "admin":
                    return jsonify({"error": "Permisos insuficientes"}), 403
                return f(sesion, *args, **kwargs)
            return decorated

        @app.route("/api/stats")
        @require_auth
        def api_stats(sesion):
            db = BaseDatos.instancia()
            stats = db.obtener_estadisticas()
            stats["espacio_gb"] = self.almacen.espacio_usado_gb()
            return jsonify(stats)

        @app.route("/api/eventos")
        @require_auth
        def api_eventos(sesion):
            filtros = {
                "tipo": request.args.get("tipo"),
                "camara_id": request.args.get("camara_id"),
                "fecha_desde": request.args.get("fecha_desde"),
                "fecha_hasta": request.args.get("fecha_hasta"),
                "placa": request.args.get("placa"),
            }
            filtros = {k: v for k, v in filtros.items() if v}
            limite = min(int(request.args.get("limite", 50)), 500)
            offset = int(request.args.get("offset", 0))
            eventos = BaseDatos.instancia().obtener_eventos(filtros, limite, offset)
            return jsonify({"items": eventos, "total": len(eventos)})

        @app.route("/api/camaras")
        @require_auth
        def api_camaras(sesion):
            camaras_info = []
            for g in self.gestores:
                camaras_info.append({
                    "id": g.config["id"],
                    "nombre": g.config["nombre"],
                    "descripcion": g.config["descripcion"],
                    "estado": g.estado,
                    "stats": g.stats,
                })
            return jsonify({"camaras": camaras_info})

        @app.route("/api/almacenamiento")
        @require_auth
        def api_almacenamiento(sesion):
            def carpeta_gb(p: Path) -> float:
                total = sum(f.stat().st_size for f in p.rglob("*.jpg") if f.is_file())
                return total / (1024 ** 3)

            return jsonify({
                "usado_gb": self.almacen.espacio_usado_gb(),
                "max_gb": CONFIG["max_gb_total"],
                "personas_gb": carpeta_gb(self.almacen.carpetas["personas"]),
                "vehiculos_gb": carpeta_gb(self.almacen.carpetas["vehiculos"]),
                "placas_gb": carpeta_gb(self.almacen.carpetas["placas"]),
                "ruta": str(self.almacen.base),
            })

        @app.route("/api/usuarios")
        @require_admin
        def api_usuarios(sesion):
            return jsonify({"usuarios": BaseDatos.instancia().obtener_usuarios()})

        @app.route("/api/usuarios", methods=["POST"])
        @require_admin
        def api_crear_usuario(sesion):
            data = request.get_json(force=True, silent=True) or {}
            username = str(data.get("username", "")).strip()[:30]
            password = str(data.get("password", ""))[:128]
            rol = data.get("rol", "viewer")

            if not username or not password or len(password) < 8:
                return jsonify({"error": "Datos inválidos. Contraseña mín. 8 caracteres"}), 400

            if rol not in ["admin", "viewer"]:
                rol = "viewer"

            ok = BaseDatos.instancia().crear_usuario(username, password, rol)
            if ok:
                return jsonify({"ok": True})
            return jsonify({"error": "El usuario ya existe"}), 409

        @app.route("/api/cambiar-password", methods=["POST"])
        @require_auth
        def api_cambiar_password(sesion):
            data = request.get_json(force=True, silent=True) or {}
            actual = str(data.get("password_actual", ""))[:128]
            nueva = str(data.get("password_nueva", ""))[:128]

            if len(nueva) < 8:
                return jsonify({"error": "Mínimo 8 caracteres"}), 400

            # Verificar contraseña actual
            usuario = BaseDatos.instancia().verificar_usuario(sesion["username"], actual)
            if not usuario:
                return jsonify({"error": "Contraseña actual incorrecta"}), 403

            BaseDatos.instancia().cambiar_password(sesion["usuario_id"], nueva)
            return jsonify({"ok": True})

        @app.route("/api/sistema-info")
        @require_admin
        def api_sistema_info(sesion):
            uptime = str(datetime.now() - self.inicio).split(".")[0]
            return jsonify({
                "python": sys.version.split()[0],
                "opencv": cv2.__version__,
                "yolo": YOLO_DISPONIBLE,
                "ocr": OCR_DISPONIBLE,
                "camaras_activas": sum(1 for g in self.gestores if g.corriendo),
                "uptime": uptime,
            })

        @app.route("/favicon.ico")
        def favicon():
            return "", 204

        # Manejo de errores
        @app.errorhandler(404)
        def not_found(e):
            return jsonify({"error": "No encontrado"}), 404

        @app.errorhandler(405)
        def method_not_allowed(e):
            return jsonify({"error": "Método no permitido"}), 405

        @app.errorhandler(413)
        def request_too_large(e):
            return jsonify({"error": "Solicitud demasiado grande"}), 413

    def _generar_ssl(self) -> Optional[Tuple[str, str]]:
        """Genera certificado SSL auto-firmado."""
        if not SSL_DISPONIBLE:
            return None

        ssl_dir = GestorAlmacenamiento().carpetas["ssl"]
        cert_file = ssl_dir / "cert.pem"
        key_file = ssl_dir / "key.pem"

        if cert_file.exists() and key_file.exists():
            return str(cert_file), str(key_file)

        try:
            print("  Generando certificado SSL auto-firmado...")
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096,
                backend=default_backend()
            )
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Red Local"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sistema Vigilancia"),
                x509.NameAttribute(NameOID.COMMON_NAME, "vigilancia.local"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=3650))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("localhost"),
                        x509.DNSName("vigilancia.local"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                        x509.IPAddress(ipaddress.ip_address(self._obtener_ip_local())),
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256(), default_backend())
            )

            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Proteger archivos
            os.chmod(str(key_file), 0o600)
            os.chmod(str(cert_file), 0o644)

            print(f"  ✓ Certificado SSL generado")
            return str(cert_file), str(key_file)
        except Exception as e:
            print(f"  ⚠ No se pudo generar SSL: {e}")
            return None

    def iniciar(self):
        """Inicia el servidor web."""
        ssl_ctx = self._generar_ssl() if CONFIG.get("web_ssl", False) else None

        host = CONFIG["web_host"]
        port = CONFIG["web_port"]
        mostrar_host = "127.0.0.1" if host in ("0.0.0.0", "127.0.0.1", "localhost") else host
        esquema = "https" if ssl_ctx else "http"

        print(f"\n  {'═'*50}")
        print(f"  Panel web: {esquema}://{mostrar_host}:{port}")
        if host == "127.0.0.1":
            print("  Modo privado: solo accesible desde esta PC")
        else:
            print("  Accesible en la red local si el Firewall de Windows lo permite")
        print(f"  {'═'*50}\n")

        # Desactivar logs de Flask en producción
        log_flask = logging.getLogger("werkzeug")
        log_flask.setLevel(logging.ERROR)

        import ssl as ssl_mod
        if ssl_ctx:
            context = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(ssl_ctx[0], ssl_ctx[1])
            context.minimum_version = getattr(ssl_mod.TLSVersion, "TLSv1_3", ssl_mod.TLSVersion.TLSv1_2)
            context.options |= ssl_mod.OP_NO_COMPRESSION
            self.app.run(
                host=host, port=port,
                ssl_context=context,
                threaded=True, debug=False,
                use_reloader=False
            )
        else:
            self.app.run(
                host=host, port=port,
                threaded=True, debug=False,
                use_reloader=False
            )

    def _obtener_ip_local(self) -> str:
        """Obtiene una IP local sin conectar a internet."""
        try:
            host = socket.gethostname()
            for info in socket.getaddrinfo(host, None, socket.AF_INET):
                ip = info[4][0]
                if ip.startswith(("192.168.", "10.")) or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", ip):
                    return ip
        except Exception:
            pass
        return "127.0.0.1"


# ══════════════════════════════════════════════════════════════════
# FASE 7: TAREAS EN BACKGROUND
# ══════════════════════════════════════════════════════════════════

def tarea_limpieza_periodica(almacen: GestorAlmacenamiento):
    """Thread que ejecuta limpieza automática periódicamente."""
    log = logging.getLogger("vigilancia.limpieza")
    while True:
        try:
            time.sleep(CONFIG["limpieza_cada_min"] * 60)
            espacio = almacen.espacio_usado_gb()
            log.info(f"Revisión de espacio: {espacio:.2f} GB / {CONFIG['max_gb_total']} GB")
            if espacio >= CONFIG["max_gb_total"] * 0.95:
                log.warning(f"Espacio al {espacio/CONFIG['max_gb_total']*100:.0f}%, limpiando...")
                almacen.limpiar_archivos_antiguos()
            BaseDatos.instancia().limpiar_sesiones_expiradas()
        except Exception as e:
            log.error(f"Error en limpieza: {e}")

def tarea_watchdog(gestores: list):
    """Thread que reinicia cámaras caídas automáticamente."""
    log = logging.getLogger("vigilancia.watchdog")
    while True:
        time.sleep(30)
        for g in gestores:
            if g.config.get("activa", True) and g.corriendo:
                if g.thread and not g.thread.is_alive():
                    log.warning(f"Cámara {g.config['nombre']} caída, reiniciando...")
                    try:
                        g.corriendo = True
                        g.thread = threading.Thread(
                            target=g._procesar_loop,
                            name=f"cam_{g.config['id']}_restart",
                            daemon=True
                        )
                        g.thread.start()
                    except Exception as e:
                        log.error(f"No se pudo reiniciar cámara: {e}")


# ══════════════════════════════════════════════════════════════════
# FASE 8: CONFIGURACIÓN DE LOGGING
# ══════════════════════════════════════════════════════════════════

def configurar_logging(almacen: GestorAlmacenamiento):
    """Configura el sistema de logging con rotación."""
    log_dir = almacen.carpetas["logs"]
    log_file = log_dir / f"vigilancia_{datetime.now().strftime('%Y%m%d')}.log"

    # Formato rico
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Handler a archivo
    fh = logging.FileHandler(str(log_file), encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    # Handler a consola
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)

    # Logger raíz
    root_log = logging.getLogger("vigilancia")
    root_log.setLevel(logging.DEBUG)
    root_log.addHandler(fh)
    root_log.addHandler(ch)

    return root_log




def _es_ip_privada_o_local(ip_txt: str) -> bool:
    """True solo para IP privada, loopback o link-local. No consulta internet."""
    try:
        ip = ipaddress.ip_address(ip_txt.strip())
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False


def validar_configuracion_privacidad() -> None:
    """Endurece configuración antes de arrancar. Falla cerrado ante cámaras externas."""
    from urllib.parse import urlparse

    if CONFIG.get("web_host") == "0.0.0.0":
        print("  ⚠ Seguridad: web_host=0.0.0.0 expone el panel en todas las interfaces.")
        print("    Cambiando automáticamente a 127.0.0.1 para máxima privacidad.")
        CONFIG["web_host"] = "127.0.0.1"

    if CONFIG.get("forzar_https", True):
        CONFIG["web_ssl"] = True
        if int(CONFIG.get("web_port", 8443)) == 8080:
            CONFIG["web_port"] = 8443

    if not CONFIG.get("permitir_rtsp_fuera_lan", False):
        for cam in CONFIG.get("camaras", []):
            if not cam.get("activa", True):
                continue
            url = cam.get("url", "")
            host = urlparse(url).hostname
            if not host:
                raise SystemExit(f"ERROR privacidad: cámara {cam.get('nombre')} no tiene host RTSP válido.")
            # Por privacidad no resolvemos DNS aquí; exige IP privada/local explícita.
            if not _es_ip_privada_o_local(host):
                raise SystemExit(
                    "ERROR privacidad: la cámara '%s' usa un host que no es IP privada/local: %s\n"
                    "Usa una IP LAN tipo 192.168.x.x / 10.x.x.x / 172.16-31.x.x, "
                    "o cambia permitir_rtsp_fuera_lan=True bajo tu responsabilidad."
                    % (cam.get("nombre"), host)
                )


def ocultar_url_rtsp(url: str) -> str:
    """Oculta usuario/contraseña al imprimir URLs RTSP."""
    try:
        from urllib.parse import urlsplit, urlunsplit
        u = urlsplit(url)
        if "@" not in u.netloc:
            return url
        host = u.hostname or ""
        if u.port:
            host = f"{host}:{u.port}"
        return urlunsplit((u.scheme, f"***:***@{host}", u.path, u.query, u.fragment))
    except Exception:
        return "rtsp://***:***@***"

# ══════════════════════════════════════════════════════════════════
# PUNTO DE ENTRADA PRINCIPAL
# ══════════════════════════════════════════════════════════════════

def main():
    print("\n" + "═" * 60)
    print("  SISTEMA DE VIGILANCIA INTELIGENTE v2.0")
    print("  Iniciando todos los subsistemas...")
    print("═" * 60 + "\n")

    validar_configuracion_privacidad()

    # ── 1. Almacenamiento ──────────────────────────────────────────
    almacen = GestorAlmacenamiento()
    almacen.inicializar()

    # ── 2. Logging ─────────────────────────────────────────────────
    log = configurar_logging(almacen)
    log.info("Sistema de vigilancia iniciado")

    # ── 3. Base de datos ───────────────────────────────────────────
    print("═" * 60)
    print("  INICIALIZANDO BASE DE DATOS")
    print("═" * 60)
    db = BaseDatos.instancia()
    print(f"  ✓ Base de datos: {db.ruta_db}\n")

    # ── 4. Motor de detección ──────────────────────────────────────
    print("═" * 60)
    print("  CARGANDO MOTORES DE DETECCIÓN")
    print("═" * 60)
    motor = MotorDeteccion()

    # ── 5. Cámaras ─────────────────────────────────────────────────
    print("═" * 60)
    print("  INICIANDO CÁMARAS RTSP")
    print("═" * 60)
    gestores = []
    for cam_config in CONFIG["camaras"]:
        g = GestorCamara(cam_config, motor, almacen)
        if cam_config.get("activa", True):
            print(f"  → Cámara {cam_config['id']}: {cam_config['nombre']}")
            print(f"    URL: {ocultar_url_rtsp(cam_config['url']) if CONFIG.get('ocultar_credenciales_logs', True) else cam_config['url']}")
            print(f"    Guardar: "
                  f"{'👤 Personas ' if cam_config['guardar_personas'] else ''}"
                  f"{'🚗 Vehículos ' if cam_config['guardar_vehiculos'] else ''}"
                  f"{'🔢 Placas' if cam_config['guardar_placas'] else ''}")
            g.iniciar()
        gestores.append(g)
    print()

    # ── 6. Tareas en background ────────────────────────────────────
    threading.Thread(
        target=tarea_limpieza_periodica, args=(almacen,),
        name="limpieza", daemon=True
    ).start()

    threading.Thread(
        target=tarea_watchdog, args=(gestores,),
        name="watchdog", daemon=True
    ).start()

    log.info("Todos los subsistemas iniciados")

    # ── 7. Manejo de señales ───────────────────────────────────────
    def signal_handler(sig, frame):
        print("\n\n  Apagando sistema...")
        for g in gestores:
            g.detener()
        log.info("Sistema apagado limpiamente")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ── 8. Servidor web (bloqueante) ───────────────────────────────
    print("═" * 60)
    print("  INICIANDO PANEL WEB")
    print("═" * 60)
    servidor = ServidorWeb(gestores, almacen)
    servidor.iniciar()  # Bloquea aquí


if __name__ == "__main__":
    main()
