"""
Password Strength Analyzer
Autor: Ignacio García Calderón
GitHub: github.com/ignacio-garcia-calderon

Herramienta de línea de comandos que evalúa la fortaleza de una contraseña
usando criterios reales de ciberseguridad: longitud, complejidad, entropía
y comparación contra contraseñas filtradas conocidas.
"""

import math
import string
import sys


# ─── Contraseñas más comunes (lista reducida de Have I Been Pwned / RockYou) ───

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "football", "monkey",
    "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "superman", "1qaz2wsx", "7777777", "fuckyou",
    "121212", "000000", "qazwsx", "123qwe", "killer",
    "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
    "hunter", "buster", "soccer", "harley", "batman",
    "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger",
    "daniel", "starwars", "klaster", "112233", "george",
    "computer", "michelle", "jessica", "pepper", "1111",
    "zxcvbn", "555555", "11111111", "131313", "freedom",
    "777777", "pass", "maggie", "159753", "aaaaaa",
    "ginger", "princess", "joshua", "cheese", "amanda",
    "summer", "love", "ashley", "6969", "nicole",
    "chelsea", "biteme", "matthew", "access", "yankees",
    "987654321", "dallas", "austin", "thunder", "taylor",
    "matrix", "mobilemail", "mom", "monitor", "homestead",
}


# ─── Cálculo de entropía ────────────────────────────────────────────────────

def calcular_entropia(password: str) -> float:
    """
    Calcula la entropía de la contraseña en bits.
    Fórmula: H = L × log2(N)
    donde L = longitud y N = tamaño del conjunto de caracteres usados.
    """
    charset = 0
    if any(c in string.ascii_lowercase for c in password):
        charset += 26
    if any(c in string.ascii_uppercase for c in password):
        charset += 26
    if any(c in string.digits for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += 32

    if charset == 0:
        return 0.0

    return len(password) * math.log2(charset)


# ─── Análisis principal ─────────────────────────────────────────────────────

def analizar_password(password: str) -> dict:
    """
    Analiza la contraseña y devuelve un diccionario con:
    - criterios cumplidos
    - puntaje (0–100)
    - nivel de fortaleza
    - sugerencias de mejora
    - entropía en bits
    """
    criterios = {
        "longitud_minima":    len(password) >= 8,
        "longitud_buena":     len(password) >= 12,
        "longitud_excelente": len(password) >= 16,
        "tiene_minuscula":    any(c in string.ascii_lowercase for c in password),
        "tiene_mayuscula":    any(c in string.ascii_uppercase for c in password),
        "tiene_numero":       any(c in string.digits for c in password),
        "tiene_simbolo":      any(c in string.punctuation for c in password),
        "no_es_comun":        password.lower() not in COMMON_PASSWORDS,
        "sin_repeticiones":   not any(password[i] == password[i+1] == password[i+2]
                                      for i in range(len(password) - 2)),
    }

    # Puntaje base por criterios
    puntaje = 0
    if criterios["longitud_minima"]:    puntaje += 10
    if criterios["longitud_buena"]:     puntaje += 15
    if criterios["longitud_excelente"]: puntaje += 15
    if criterios["tiene_minuscula"]:    puntaje += 10
    if criterios["tiene_mayuscula"]:    puntaje += 10
    if criterios["tiene_numero"]:       puntaje += 10
    if criterios["tiene_simbolo"]:      puntaje += 15
    if criterios["no_es_comun"]:        puntaje += 10
    if criterios["sin_repeticiones"]:   puntaje += 5

    # Bonus por entropía alta
    entropia = calcular_entropia(password)
    if entropia >= 60:  puntaje += 5
    if entropia >= 80:  puntaje += 5

    puntaje = min(puntaje, 100)

    # Nivel de fortaleza
    if puntaje < 30:
        nivel = "Muy débil"
        color = "\033[91m"    # rojo
    elif puntaje < 50:
        nivel = "Débil"
        color = "\033[93m"    # amarillo
    elif puntaje < 70:
        nivel = "Media"
        color = "\033[94m"    # azul
    elif puntaje < 90:
        nivel = "Fuerte"
        color = "\033[92m"    # verde
    else:
        nivel = "Muy fuerte"
        color = "\033[92m"    # verde

    # Sugerencias
    sugerencias = []
    if not criterios["longitud_minima"]:
        sugerencias.append("Usá al menos 8 caracteres.")
    elif not criterios["longitud_buena"]:
        sugerencias.append("Intentá llegar a 12 caracteres o más.")
    elif not criterios["longitud_excelente"]:
        sugerencias.append("16 caracteres o más es ideal para cuentas importantes.")
    if not criterios["tiene_minuscula"]:
        sugerencias.append("Agregá letras minúsculas.")
    if not criterios["tiene_mayuscula"]:
        sugerencias.append("Agregá al menos una letra mayúscula.")
    if not criterios["tiene_numero"]:
        sugerencias.append("Incluí al menos un número.")
    if not criterios["tiene_simbolo"]:
        sugerencias.append("Usá símbolos como !, @, #, $, % para mayor seguridad.")
    if not criterios["no_es_comun"]:
        sugerencias.append("Esta contraseña es muy conocida y está en listas de hackeos. Cambiála.")
    if not criterios["sin_repeticiones"]:
        sugerencias.append("Evitá tres o más caracteres iguales seguidos (ej: 'aaa').")

    return {
        "password":    password,
        "puntaje":     puntaje,
        "nivel":       nivel,
        "color":       color,
        "entropia":    round(entropia, 1),
        "criterios":   criterios,
        "sugerencias": sugerencias,
    }


# ─── Visualización en consola ───────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
VERDE  = "\033[92m"
ROJO   = "\033[91m"
GRIS   = "\033[90m"
BLANCO = "\033[97m"


def barra_puntaje(puntaje: int, ancho: int = 30) -> str:
    """Genera una barra de progreso visual para el puntaje."""
    llenos = int((puntaje / 100) * ancho)
    vacios = ancho - llenos
    if puntaje < 30:
        color = "\033[91m"
    elif puntaje < 60:
        color = "\033[93m"
    else:
        color = "\033[92m"
    return f"{color}{'█' * llenos}{GRIS}{'░' * vacios}{RESET}"


def imprimir_resultado(resultado: dict) -> None:
    """Imprime el resultado del análisis de forma visual en la consola."""
    color  = resultado["color"]
    nivel  = resultado["nivel"]
    puntaje = resultado["puntaje"]

    print()
    print(f"  {BOLD}{'─' * 44}{RESET}")
    print(f"  {BOLD}  Análisis de contraseña{RESET}")
    print(f"  {BOLD}{'─' * 44}{RESET}")
    print()
    print(f"  Puntaje   {barra_puntaje(puntaje)}  {BOLD}{puntaje}/100{RESET}")
    print(f"  Nivel     {color}{BOLD}{nivel}{RESET}")
    print(f"  Entropía  {resultado['entropia']} bits")
    print()

    print(f"  {BOLD}Criterios:{RESET}")
    checks = [
        ("longitud_minima",    "Longitud mínima (8+)"),
        ("longitud_buena",     "Longitud recomendada (12+)"),
        ("longitud_excelente", "Longitud excelente (16+)"),
        ("tiene_minuscula",    "Contiene minúsculas"),
        ("tiene_mayuscula",    "Contiene mayúsculas"),
        ("tiene_numero",       "Contiene números"),
        ("tiene_simbolo",      "Contiene símbolos"),
        ("no_es_comun",        "No está en listas de filtraciones"),
        ("sin_repeticiones",   "Sin repeticiones seguidas"),
    ]
    for key, label in checks:
        icono = f"{VERDE}✓{RESET}" if resultado["criterios"][key] else f"{ROJO}✗{RESET}"
        print(f"    {icono}  {label}")

    if resultado["sugerencias"]:
        print()
        print(f"  {BOLD}Sugerencias:{RESET}")
        for s in resultado["sugerencias"]:
            print(f"    {GRIS}→{RESET} {s}")

    print()
    print(f"  {BOLD}{'─' * 44}{RESET}")
    print()


# ─── Modo interactivo ───────────────────────────────────────────────────────

def modo_interactivo() -> None:
    """Permite analizar múltiples contraseñas en un loop."""
    print()
    print(f"  {BOLD}Password Strength Analyzer{RESET}")
    print(f"  {GRIS}por Ignacio García Calderón{RESET}")
    print(f"  {GRIS}Escribí 'salir' para terminar.{RESET}")

    while True:
        print()
        try:
            password = input("  Contraseña: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n  Hasta luego.\n")
            break

        if password.lower() in ("salir", "exit", "q"):
            print("\n  Hasta luego.\n")
            break

        if not password:
            print(f"  {ROJO}Ingresá una contraseña.{RESET}")
            continue

        resultado = analizar_password(password)
        imprimir_resultado(resultado)


# ─── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Modo argumento: python password_analyzer.py miContraseña123
        password = " ".join(sys.argv[1:])
        resultado = analizar_password(password)
        imprimir_resultado(resultado)
    else:
        # Modo interactivo
        modo_interactivo()
