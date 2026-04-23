# Password Strength Analyzer 🔐

Herramienta de línea de comandos en Python que evalúa la fortaleza de una contraseña usando criterios reales de ciberseguridad.

## ¿Qué analiza?

- **Longitud** — mínima (8), recomendada (12) y excelente (16+)
- **Complejidad** — mayúsculas, minúsculas, números y símbolos
- **Entropía** — qué tan impredecible es la contraseña en bits
- **Filtraciones** — comparación contra contraseñas comunes conocidas (basado en Have I Been Pwned / RockYou)
- **Repeticiones** — detecta patrones como `aaa` o `111`

## Demo

```
  ────────────────────────────────────────────────
    Análisis de contraseña
  ────────────────────────────────────────────────

  Puntaje   ████████████████░░░░░░░░░░░░░░  55/100
  Nivel     Media
  Entropía  52.7 bits

  Criterios:
    ✓  Longitud mínima (8+)
    ✓  Longitud recomendada (12+)
    ✗  Longitud excelente (16+)
    ✓  Contiene minúsculas
    ✓  Contiene mayúsculas
    ✓  Contiene números
    ✗  Contiene símbolos
    ✓  No está en listas de filtraciones
    ✓  Sin repeticiones seguidas

  Sugerencias:
    → 16 caracteres o más es ideal para cuentas importantes.
    → Usá símbolos como !, @, #, $, % para mayor seguridad.

  ────────────────────────────────────────────────
```

## Instalación

No requiere librerías externas. Solo necesitás Python 3.6 o superior.

```bash
git clone https://github.com/ignacio-garcia-calderon/password-analyzer.git
cd password-analyzer
```

## Uso

**Modo interactivo** (recomendado):
```bash
python password_analyzer.py
```

**Modo argumento directo:**
```bash
python password_analyzer.py MiContraseña123!
```

## Puntaje y niveles

| Puntaje | Nivel       |
|---------|-------------|
| 0–29    | Muy débil   |
| 30–49   | Débil       |
| 50–69   | Media       |
| 70–89   | Fuerte      |
| 90–100  | Muy fuerte  |

## Tecnologías

- Python 3
- Módulos estándar: `math`, `string`, `sys`

## Autor

**Ignacio García Calderón**  
Estudiante de Ingeniería en Sistemas — UTN Rosario  
[LinkedIn](https://linkedin.com/in/ignacio-garcia-calderon) · [GitHub](https://github.com/ignacio-garcia-calderon)
