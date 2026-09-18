"""Parser y traductor de diagnósticos crudos de AddressSanitizer y UBSan."""

import re
from typing import List, Optional
from tetsuo.core.models import SanitizerDiagnosis, SanitizerType, SanitizerReport

ASAN_HEADER = re.compile(r'==\d+==ERROR: AddressSanitizer: ([a-zA-Z\-]+) on address ([0-9a-fx]+)')
UBSAN_HEADER = re.compile(r'runtime error: (.*)')
# ASan en Linux activa LeakSanitizer por defecto, y su cabecera NO es la de
# AddressSanitizer: sin este patrón, el error más común del curso (olvidarse el
# `free`) llegaba sin traducir.
LSAN_HEADER = re.compile(r'==\d+==ERROR: LeakSanitizer: detected memory leaks')
FRAME_DE_USUARIO = re.compile(r'#\d+\s+[0-9a-fx]+\s+in\s+([a-zA-Z0-9_]+)\s+([^\s:()]+\.[ch]):(\d+)')
LSAN_LEAK = re.compile(r'(Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\) allocated from:')
STACK_FRAME = re.compile(r'#0\s+([0-9a-fx]+)\s+in\s+([a-zA-Z0-9_]+)\s+([^:]+):(\d+)')
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
    "double-free": (
        "Doble Liberación de Memoria (Double Free)",
        "Se invocó 'free()' dos veces sobre la misma dirección de memoria dinámica.",
        "Asegurate de que cada llamada a malloc tenga exactamente una llamada a free."
    ),
}


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
        diagnoses.append(SanitizerDiagnosis(
            sanitizer_type=SanitizerType.UBSAN,
            error_tag="undefined-behavior",
            title_es="Comportamiento Indefinido (Undefined Behavior)",
            explanation_es=f"Se produjo una operación no permitida por el estándar de C: {msg}",
            suggestion_es="Corregí la operación para evitar que el compilador genere código impredecible o erróneo.",
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
