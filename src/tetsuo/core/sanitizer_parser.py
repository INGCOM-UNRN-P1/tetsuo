"""Parser y traductor de diagnósticos crudos de AddressSanitizer y UBSan."""

import re
from typing import List, Optional
from tetsuo.core.models import SanitizerDiagnosis, SanitizerType, SanitizerReport

ASAN_HEADER = re.compile(r'==\d+==ERROR: AddressSanitizer: ([a-zA-Z\-]+) on (?:unknown )?address ([0-9a-fx]+)')
UBSAN_HEADER = re.compile(r'runtime error: (.*)')
# ASan en Linux activa LeakSanitizer por defecto, y su cabecera NO es la de
# AddressSanitizer: sin este patrón, el error más común del curso (olvidarse el
# `free`) llegaba sin traducir.
LSAN_HEADER = re.compile(r'==\d+==ERROR: LeakSanitizer: detected memory leaks')
# `(?:[A-Za-z]:)?`: en Windows la ruta empieza con la letra de unidad (C:\...), cuyos dos puntos no
# separan el archivo de la línea (N-ECO-22).
FRAME_DE_USUARIO = re.compile(r'#\d+\s+[0-9a-fx]+\s+in\s+([a-zA-Z0-9_]+)\s+((?:[A-Za-z]:)?[^\s:()]+\.[ch]):(\d+)')
LSAN_LEAK = re.compile(r'(Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:')
STACK_FRAME = re.compile(r'#0\s+([0-9a-fx]+)\s+in\s+([a-zA-Z0-9_]+)\s+((?:[A-Za-z]:)?[^:]+):(\d+)')
ACCESS_PATTERN = re.compile(r'(READ|WRITE) of size (\d+)')

CATALOGO_ERRORES = {
    "heap-buffer-overflow": (
        "Desbordamiento de Búfer en el Heap",
        "Tu programa intentó leer o escribir bytes fuera del bloque de memoria dinámica asignado con malloc/calloc.",
        "Verificá los límites de tus bucles al recorrer arrays en Heap y asegurate de multiplicar por sizeof(tipo) al allocar."
    ),
    "stack-buffer-overflow": (
        "Desbordamiento de Búfer en la Pila (Stack)",
        "Tu programa sobrepasó el límite de un array local declarado en el Stack.",
        "Chequeá que los índices de arrays locales no alcancen 'N' (los arreglos en C van de 0 a N-1) y evitá funciones inseguras como gets/strcpy."
    ),
    "global-buffer-overflow": (
        "Desbordamiento de Variable Global",
        "Se accedió fuera de los límites de un array estático o global.",
        "Revisá el tamaño definido en la constante del array global."
    ),
    "heap-use-after-free": (
        "Uso de Memoria tras Liberación (Use-After-Free)",
        "Intentaste leer o escribir en un puntero cuya memoria ya fue liberada con 'free()'.",
        "Asigná 'ptr = NULL;' inmediatamente después de llamar a 'free(ptr)' para prevenir accesos accidentales."
    ),
    "stack-use-after-return": (
        "Uso de Variable de Pila tras Retorno de Función",
        "Una función retornó un puntero a una variable local de su Stack Frame, el cual fue destruido al retornar.",
        "No retornes punteros a variables locales. Asigná la memoria en el Heap con malloc o pasá el búfer como parámetro."
    ),
    "stack-use-after-scope": (
        "Uso de una Variable Local fuera de su Bloque",
        "Se usó la dirección de una variable declarada dentro de un bloque { ... } (un if, un for) después de "
        "que el bloque terminó: esa variable ya no existe.",
        "Declará la variable en el bloque donde la vas a seguir usando, o copiá su valor antes de salir del bloque."
    ),
    "segv": (
        "Acceso a una Dirección Inválida (Segmentation Fault)",
        "El programa leyó o escribió en una dirección que no le pertenece: casi siempre un puntero NULL, sin "
        "inicializar o ya liberado.",
        "Inicializá los punteros al declararlos, verificá NULL después de malloc/fopen y no los uses después de free."
    ),
    "bad-free": (
        "free() sobre una Dirección que no Vino de malloc",
        "Se llamó a free() con un puntero que no devolvió malloc/calloc/realloc (una variable local, un literal o "
        "un puntero desplazado con aritmética).",
        "Pasale a free() exactamente el puntero que devolvió malloc, sin moverlo, y solo una vez."
    ),
    "alloc-dealloc-mismatch": (
        "Reserva y Liberación que no Coinciden",
        "La memoria se reservó con una función y se liberó con otra que no le corresponde.",
        "Liberá con free() lo que reservaste con malloc/calloc/realloc."
    ),
    "double-free": (
        "Doble Liberación de Memoria (Double Free)",
        "Se invocó 'free()' dos veces sobre la misma dirección de memoria dinámica.",
        "Asegurate de que cada llamada a malloc tenga exactamente una llamada a free."
    ),
}


# UBSan: (patrón del mensaje, tag, título, explicación, sugerencia). Antes todos salían como un
# «comportamiento indefinido» genérico con el mensaje en inglés.
_UBSAN: List[tuple] = [
    (r"signed integer overflow", "signed-integer-overflow", "Desborde de un Entero con Signo",
     "El resultado de una suma, resta o multiplicación no entra en el tipo (por ejemplo, pasa INT_MAX): en C "
     "eso es comportamiento indefinido, no «da la vuelta».",
     "Verificá los límites antes de operar (INT_MAX en <limits.h>) o usá un tipo más grande (long long)."),
    (r"division by zero", "division-by-zero", "División por Cero",
     "Se dividió (o se calculó el resto) por cero.",
     "Verificá que el divisor no sea cero antes de dividir."),
    (r"shift exponent|left shift of", "shift-out-of-bounds", "Desplazamiento de Bits Inválido",
     "Se desplazó un valor una cantidad de bits negativa, mayor o igual al ancho del tipo, o un negativo a la "
     "izquierda.",
     "Desplazá solo entre 0 y el ancho del tipo menos uno, y preferí tipos sin signo para operar con bits."),
    (r"index -?\d+ out of bounds", "array-index-out-of-bounds", "Índice Fuera de los Límites del Arreglo",
     "Se accedió a un arreglo con un índice fuera de su rango (de 0 a N-1).",
     "Revisá las condiciones de los lazos: con N elementos, el último índice válido es N-1."),
    (r"null pointer", "null-pointer", "Uso de un Puntero NULL",
     "Se leyó, escribió o accedió a un campo a través de un puntero que vale NULL.",
     "Verificá que el puntero no sea NULL antes de usarlo (por ejemplo, después de malloc o fopen)."),
    (r"misaligned address", "misaligned", "Acceso Desalineado",
     "Se accedió a un dato a través de un puntero que no respeta la alineación de su tipo (un int * dentro "
     "de un char[]).",
     "Copiá los bytes con memcpy en lugar de convertir punteros entre tipos distintos."),
    (r"is outside the range of representable values|implicit conversion", "conversion", "Conversión fuera de Rango",
     "Un valor no entra en el tipo al que se lo convierte.",
     "Verificá el rango antes de convertir o usá un tipo que pueda representarlo."),
]


def traducir_ubsan(mensaje: str) -> tuple:
    for patron, tag, titulo, explicacion, sugerencia in _UBSAN:
        if re.search(patron, mensaje, re.IGNORECASE):
            return tag, titulo, explicacion, sugerencia
    return ("undefined-behavior", "Comportamiento Indefinido (Undefined Behavior)",
            "Se produjo una operación no permitida por el estándar de C",
            "Corregí la operación para evitar que el compilador genere código impredecible o erróneo.")


def parse_sanitizer_output(raw_text: str) -> List[SanitizerDiagnosis]:
    """Parsea texto crudo de stderr y genera diagnósticos pedagógicos estructurados."""
    diagnoses = []

    # 1. AddressSanitizer
    match_asan = ASAN_HEADER.search(raw_text)
    if match_asan:
        tag = match_asan.group(1).lower()
        addr = match_asan.group(2)
        access_match = ACCESS_PATTERN.search(raw_text)
        access_type = access_match.group(1) if access_match else "ACCESO"

        info = CATALOGO_ERRORES.get(tag, (
            f"Fallo de Memoria ({tag})",
            "Error de acceso indebido a memoria detectado por AddressSanitizer.",
            "Revisá la gestión de punteros y memoria dinámica en tu código."
        ))

        # Extraer stack frame superior (#0)
        frame_match = STACK_FRAME.search(raw_text)
        fn_name = frame_match.group(2) if frame_match else "desconocida"
        file_path = frame_match.group(3) if frame_match else None
        line_no = int(frame_match.group(4)) if frame_match else None

        diagnoses.append(SanitizerDiagnosis(
            sanitizer_type=SanitizerType.ASAN,
            error_tag=tag,
            title_es=info[0],
            explanation_es=info[1],
            file_path=file_path,
            line_number=line_no,
            function_name=fn_name,
            memory_address=addr,
            access_type=access_type,
            suggestion_es=info[2],
            raw_snippet=match_asan.group(0)
        ))

    # 2. UndefinedBehaviorSanitizer
    for ubsan_match in UBSAN_HEADER.finditer(raw_text):
        msg = ubsan_match.group(1).strip()
        tag, titulo, explicacion, sugerencia = traducir_ubsan(msg)
        inicio = raw_text.rfind("\n", 0, ubsan_match.start()) + 1
        ubicacion = re.match(r"((?:[A-Za-z]:)?[^\s:]+\.[ch]):(\d+):\d+:", raw_text[inicio:ubsan_match.start()])
        diagnoses.append(SanitizerDiagnosis(
            sanitizer_type=SanitizerType.UBSAN,
            error_tag=tag,
            title_es=titulo,
            explanation_es=f"{explicacion} (UBSan: {msg})",
            file_path=ubicacion.group(1) if ubicacion else None,
            line_number=int(ubicacion.group(2)) if ubicacion else None,
            suggestion_es=sugerencia,
            raw_snippet=ubsan_match.group(0)
        ))

    # 3. LeakSanitizer
    if LSAN_HEADER.search(raw_text):
        directas = [(int(b), int(o)) for tipo, b, o in LSAN_LEAK.findall(raw_text) if tipo == "Direct"]
        total_bytes = sum(b for b, _ in directas)
        total_objetos = sum(o for _, o in directas)
        detalle = (
            f" Se perdieron {total_bytes} byte(s) en {total_objetos} bloque(s) sin liberar."
            if directas else ""
        )
        # El frame #0 de una fuga es `malloc` dentro de la librería del
        # sanitizer, sin archivo:línea; el que le sirve al estudiante es el
        # primero que cae en su propio fuente.
        frame = FRAME_DE_USUARIO.search(raw_text)
        diagnoses.append(SanitizerDiagnosis(
            sanitizer_type=SanitizerType.LSAN,
            error_tag="memory-leak",
            title_es="Fuga de Memoria (Memory Leak)",
            explanation_es=(
                "Tu programa terminó sin liberar memoria dinámica que había reservado con "
                "malloc/calloc/realloc." + detalle
            ),
            file_path=frame.group(2) if frame else None,
            line_number=int(frame.group(3)) if frame else None,
            function_name=frame.group(1) if frame else None,
            suggestion_es=(
                "Cada malloc necesita exactamente un free. Liberá el bloque cuando dejes de "
                "usarlo, incluso en las rutas de error, y recorré las estructuras enlazadas "
                "liberando nodo por nodo."
            ),
            raw_snippet=LSAN_HEADER.search(raw_text).group(0),
        ))

    return diagnoses
