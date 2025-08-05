# Script desarrollado por Marcos Sebastian Cunioli - Especialista en Ciberseguridad #

import streamlit as st
import os
import binascii
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA512, MD5 
import matplotlib.pyplot as plt
import io # For handling byte streams for downloads
import secrets # Aseguramos que secrets esté importado aquí

# Importar librerías para bcrypt y Argon2
try:
    import bcrypt
except ImportError:
    st.error("La librería 'bcrypt' no está instalada. Por favor, instálala con: pip install bcrypt")
    bcrypt = None # Set to None to prevent further errors if not installed

try:
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
except ImportError:
    st.error("La librería 'argon2-cffi' no está instalada. Por favor, instálala con: pip install argon2-cffi")
    PasswordHasher = None # Set to None to prevent further errors if not installed


# --- Streamlit Page Configuration ---
st.set_page_config(page_title="Herramientas Criptográficas", layout="centered")

# Título principal de la aplicación
st.title("🛡️ Herramientas Criptográficas")
st.markdown("---")
st.write("Script desarrollado por **Marcos Sebastian Cunioli** - Especialista en Ciberseguridad")
st.markdown("---")

st.info("""
    Este programa permite generar y explorar diversos elementos fundamentales en la seguridad criptográfica,
    como Vectores de Inicialización (IV), Nonces, Padding, Claves de cifrado, Claves derivadas,
    Hashes seguros y Números Pseudoaleatorios. También incluye una prueba de cifrado con AES en modo CBC
    y una visualización básica del proceso.
""")

# --- Helper Function for Download Buttons ---
def create_download_button(label, data, filename, mime_type):
    """Creates a download button for given data."""
    st.download_button(
        label=label,
        data=data,
        file_name=filename,
        mime=mime_type,
        key=f"download_{filename.replace('.', '_').replace('/', '_').replace(' ', '_').replace('(', '').replace(')', '')}"
    )

# --- 1. Generar Vector de Inicialización (IV) ---
with st.expander("1. Generar Vector de Inicialización (IV)", expanded=False):
    st.markdown("#### ¿Qué es un Vector de Inicialización (IV)?")
    st.info("Un IV es un valor aleatorio utilizado para garantizar que el cifrado sea único, incluso si se utiliza la misma clave. Es público pero debe ser impredecible y único para cada operación de cifrado.")
    
    iv_size = st.number_input("Ingrese el tamaño del IV (en bytes, recomendado 16 para AES):", min_value=1, value=16, step=1, key="iv_size_input")
    iv_format = st.radio("Formato de salida:", ("Hexadecimal", "Base64", "Bytes Crudos"), key="iv_format_radio")

    if st.button("Generar IV", key="generate_iv_button"):
        if iv_size > 0:
            with st.spinner("Generando IV..."):
                iv_bytes = secrets.token_bytes(iv_size) # Usando secrets.token_bytes
                
                output_data = b""
                display_text = ""
                if iv_format == "Hexadecimal":
                    output_data = iv_bytes.hex().encode('utf-8')
                    display_text = iv_bytes.hex()
                elif iv_format == "Base64":
                    output_data = base64.b64encode(iv_bytes)
                    display_text = output_data.decode('utf-8')
                elif iv_format == "Bytes Crudos":
                    output_data = iv_bytes
                    display_text = str(iv_bytes) # For display purposes

                st.success(f"Vector de Inicialización (IV) generado: `{display_text}`")
                create_download_button(f"Descargar IV ({iv_format})", output_data, f"iv_{iv_size}bytes.{iv_format.lower().replace(' ', '_')}.txt", "text/plain")
        else:
            st.error("El tamaño del IV debe ser mayor que 0.")

# --- 2. Generar Nonce ---
with st.expander("2. Generar Nonce", expanded=False):
    st.markdown("#### ¿Qué es un Nonce?")
    st.info("Un Nonce (Number used Once) es un valor aleatorio o pseudoaleatorio utilizado para inicializar ciertos modos de cifrado (como GCM), garantizando la unicidad del cifrado. Similar a un IV, pero con requisitos de unicidad más estrictos en algunos contextos.")
    
    nonce_size = st.number_input("Ingrese el tamaño del Nonce (en bytes, recomendado 12 para AES-GCM):", min_value=1, value=12, step=1, key="nonce_size_input")
    nonce_format = st.radio("Formato de salida:", ("Hexadecimal", "Base64", "Bytes Crudos"), key="nonce_format_radio")

    if st.button("Generar Nonce", key="generate_nonce_button"):
        if nonce_size > 0:
            with st.spinner("Generando Nonce..."):
                nonce_bytes = secrets.token_bytes(nonce_size) # Usando secrets.token_bytes
                
                output_data = b""
                display_text = ""
                if nonce_format == "Hexadecimal":
                    output_data = nonce_bytes.hex().encode('utf-8')
                    display_text = nonce_bytes.hex()
                elif nonce_format == "Base64":
                    output_data = base64.b64encode(nonce_bytes)
                    display_text = output_data.decode('utf-8')
                elif nonce_format == "Bytes Crudos":
                    output_data = nonce_bytes
                    display_text = str(nonce_bytes)

                st.success(f"Nonce generado: `{display_text}`")
                create_download_button(f"Descargar Nonce ({nonce_format})", output_data, f"nonce_{nonce_size}bytes.{nonce_format.lower().replace(' ', '_')}.txt", "text/plain")
        else:
            st.error("El tamaño del Nonce debe ser mayor que 0.")

# --- 3. Demostrar Padding ---
with st.expander("3. Demostrar Padding", expanded=False):
    st.markdown("#### Demostración de Padding")
    st.info("El Padding se utiliza para completar un texto claro de modo que su longitud sea un múltiplo del tamaño del bloque del cifrador, lo cual es necesario para muchos algoritmos de cifrado por bloques.")
    
    padding_scheme_select = st.selectbox(
        "Seleccione el esquema de padding:",
        ("PKCS7", "ANSI X9.23", "ISO 10126"),
        key="padding_scheme_select"
    )
    padding_plaintext_input = st.text_area("Ingrese el texto a padear:", "Texto de ejemplo para padding", key="padding_plaintext_input")
    block_size_input = st.number_input("Tamaño del bloque (bytes, ej. 16 para AES):", min_value=1, value=16, step=1, key="block_size_input")

    if st.button("Aplicar y Quitar Padding", key="demonstrate_padding_button"):
        if padding_plaintext_input and block_size_input > 0:
            with st.spinner("Demostrando padding..."):
                try:
                    plaintext_bytes = padding_plaintext_input.encode('utf-8')
                    
                    st.write(f"**Texto original:** `{plaintext_bytes}`")
                    st.write(f"**Longitud original:** {len(plaintext_bytes)} bytes")
                    
                    padded_bytes = b""
                    unpadded_bytes = b""
                    
                    # FIX: Correct style names for Crypto.Util.Padding
                    if padding_scheme_select == "PKCS7":
                        padded_bytes = pad(plaintext_bytes, block_size_input, style='pkcs7')
                        unpadded_bytes = unpad(padded_bytes, block_size_input, style='pkcs7')
                    elif padding_scheme_select == "ANSI X9.23":
                        padded_bytes = pad(plaintext_bytes, block_size_input, style='x923') # Correct style name
                        unpadded_bytes = unpad(padded_bytes, block_size_input, style='x923') # Correct style name
                    elif padding_scheme_select == "ISO 10126":
                        padded_bytes = pad(plaintext_bytes, block_size_input, style='iso7816') # Correct style name (ISO/IEC 7816-4)
                        unpadded_bytes = unpad(padded_bytes, block_size_input, style='iso7816') # Correct style name

                    st.write(f"**Esquema de Padding:** `{padding_scheme_select}`")
                    st.write(f"**Texto con padding (Hex):** `{padded_bytes.hex()}`")
                    st.write(f"**Texto con padding (Bytes):** `{padded_bytes}`")
                    st.write(f"**Longitud con padding:** {len(padded_bytes)} bytes")
                    
                    st.success(f"**Texto después de quitar padding:** `{unpadded_bytes.decode('utf-8')}`")

                except ValueError as e:
                    st.error(f"Error al aplicar/quitar padding: {e}. Esto puede ocurrir si el padding no es válido para el esquema o la longitud del bloque.")
                except Exception as e:
                    st.error(f"Error durante la demostración de padding: {e}")
        else:
            st.warning("Por favor, ingrese un texto y un tamaño de bloque válido.")

# --- 4. Funciones de Derivación de Clave (KDF) ---
with st.expander("4. Funciones de Derivación de Clave (KDF)", expanded=False):
    st.markdown("#### Funciones de Derivación de Clave (KDF)")
    st.info("Las Funciones de Derivación de Clave (KDFs) son algoritmos que transforman una contraseña o frase de paso (generalmente de baja entropía) en una clave criptográfica (de alta entropía) adecuada para usar en algoritmos de cifrado. Están diseñadas para ser computacionalmente costosas y resistentes a ataques de fuerza bruta.")
    
    # --- PBKDF2 Implementation ---
    st.markdown("##### PBKDF2 (Password-Based Key Derivation Function 2)")
    st.write("PBKDF2 es una KDF ampliamente utilizada que mejora la seguridad de las contraseñas añadiendo un 'salt' y realizando múltiples iteraciones de una función hash para hacer el proceso más lento y resistente a ataques de diccionario y tablas arcoíris.")
    
    # Initialize session state for PBKDF2 password input if it doesn't exist
    if 'pbkdf2_password_value' not in st.session_state:
        st.session_state.pbkdf2_password_value = ""

    # Callback function to clear the PBKDF2 password input
    def clear_pbkdf2_password():
        st.session_state.pbkdf2_password_value = ""

    pbkdf2_password = st.text_input(
        "Ingrese la contraseña (PBKDF2):", 
        type="password", 
        key="pbkdf2_password_widget", # Use a unique key for the widget
        value=st.session_state.pbkdf2_password_value, # Bind widget value to session state
        on_change=lambda: st.session_state.update(pbkdf2_password_value=st.session_state.pbkdf2_password_widget) # Update session state on widget change
    )

    pbkdf2_dklen = st.number_input("Longitud de la clave derivada (en bytes, ej. 32 para AES-256):", min_value=16, value=32, step=8, key="pbkdf2_dklen_input")
    pbkdf2_iterations = st.number_input("Número de iteraciones (cuanto más alto, más seguro y lento):", min_value=1000, value=100000, step=10000, key="pbkdf2_iterations_input")
    pbkdf2_format = st.radio("Formato de salida de PBKDF2:", ("Hexadecimal", "Base64", "Bytes Crudos"), key="pbkdf2_format_radio")

    if st.button("Generar Clave Derivada (PBKDF2)", key="generate_derived_key_button"):
        if pbkdf2_password:
            with st.spinner("Generando clave derivada con PBKDF2..."):
                try:
                    salt = get_random_bytes(16) # Random salt
                    key_derived_bytes = PBKDF2(pbkdf2_password.encode('utf-8'), salt, dkLen=pbkdf2_dklen, count=pbkdf2_iterations, hmac_hash_module=SHA256)
                    
                    output_data = b""
                    display_text = ""
                    if pbkdf2_format == "Hexadecimal":
                        output_data = key_derived_bytes.hex().encode('utf-8')
                        display_text = key_derived_bytes.hex()
                    elif pbkdf2_format == "Base64":
                        output_data = base64.b64encode(key_derived_bytes)
                        display_text = output_data.decode('utf-8')
                    elif pbkdf2_format == "Bytes Crudos":
                        output_data = key_derived_bytes
                        display_text = str(key_derived_bytes)

                    st.success(f"Clave derivada generada: `{display_text}`")
                    st.write(f"**Salt utilizado (Hex):** `{salt.hex()}`")
                    create_download_button(f"Descargar Clave Derivada ({pbkdf2_format})", output_data, f"derived_key_{pbkdf2_dklen}bytes.{pbkdf2_format.lower().replace(' ', '_')}.txt", "text/plain")
                    create_download_button("Descargar Salt (Hex)", salt.hex().encode('utf-8'), "pbkdf2_salt.txt", "text/plain")
                except Exception as e:
                    st.error(f"Error al generar clave derivada: {e}")
        else:
            st.warning("Por favor, ingrese una contraseña.")
    
    if st.button("Limpiar Contraseña PBKDF2", on_click=clear_pbkdf2_password, key="clear_pbkdf2_password_button"):
        pass

    st.markdown("---")
    st.markdown("##### bcrypt")
    st.write("bcrypt es una función de hash de contraseñas diseñada para ser lenta y resistente a ataques de fuerza bruta y hardware especializado (ASICs). Utiliza un factor de trabajo que puede ajustarse para aumentar la complejidad computacional con el tiempo.")
    
    if bcrypt: # Only show if bcrypt is imported successfully
        # Initialize session state for bcrypt password input if it doesn't exist
        if 'bcrypt_password_value' not in st.session_state:
            st.session_state.bcrypt_password_value = ""

        # Callback function to clear the bcrypt password input
        def clear_bcrypt_password():
            st.session_state.bcrypt_password_value = ""

        bcrypt_password = st.text_input(
            "Ingrese la contraseña (bcrypt):",
            type="password",
            key="bcrypt_password_widget",
            value=st.session_state.bcrypt_password_value,
            on_change=lambda: st.session_state.update(bcrypt_password_value=st.session_state.bcrypt_password_widget)
        )
        bcrypt_rounds = st.slider("Factor de rondas (costo, 2^rounds iteraciones):", min_value=4, max_value=16, value=12, step=1, key="bcrypt_rounds_input")
        
        if st.button("Generar Hash (bcrypt)", key="generate_bcrypt_hash_button"):
            if bcrypt_password:
                with st.spinner("Generando hash bcrypt..."):
                    try:
                        hashed_password = bcrypt.hashpw(bcrypt_password.encode('utf-8'), bcrypt.gensalt(rounds=bcrypt_rounds))
                        st.success(f"Hash bcrypt generado: `{hashed_password.decode('utf-8')}`")
                        create_download_button("Descargar Hash bcrypt", hashed_password, "bcrypt_hash.txt", "text/plain")
                    except Exception as e:
                        st.error(f"Error al generar hash bcrypt: {e}")
            else:
                st.warning("Por favor, ingrese una contraseña para bcrypt.")
        
        if st.button("Limpiar Contraseña bcrypt", on_click=clear_bcrypt_password, key="clear_bcrypt_password_button"):
            pass
    else:
        st.info("*(La implementación de bcrypt requiere la librería `bcrypt`.)*")


    st.markdown("---")
    st.markdown("##### scrypt")
    st.write("scrypt es una KDF que, además de ser computacionalmente costosa, requiere una cantidad significativa de memoria RAM para su ejecución. Esto la hace particularmente resistente a ataques que utilizan hardware especializado (ASICs y FPGAs) y ataques paralelos.")
    
    # --- scrypt Implementation ---
    # Initialize session state for scrypt password input if it doesn't exist
    if 'scrypt_password_value' not in st.session_state:
        st.session_state.scrypt_password_value = ""

    # Callback function to clear the scrypt password input
    def clear_scrypt_password():
        st.session_state.scrypt_password_value = ""

    scrypt_password = st.text_input(
        "Ingrese la contraseña (scrypt):",
        type="password",
        key="scrypt_password_widget",
        value=st.session_state.scrypt_password_value,
        on_change=lambda: st.session_state.update(scrypt_password_value=st.session_state.scrypt_password_widget)
    )
    # scrypt parameters: N (CPU/memory cost), r (block size), p (parallelization), dklen (derived key length)
    scrypt_n = st.number_input("Costo N (iteraciones, potencia de 2, ej. 2^14 = 16384):", min_value=2, value=16384, step=1024, key="scrypt_n_input")
    scrypt_r = st.number_input("Costo r (tamaño de bloque):", min_value=1, value=8, step=1, key="scrypt_r_input")
    scrypt_p = st.number_input("Costo p (paralelismo):", min_value=1, value=1, step=1, key="scrypt_p_input")
    scrypt_dklen = st.number_input("Longitud de clave derivada (bytes, ej. 32):", min_value=16, value=32, step=8, key="scrypt_dklen_input")

    if st.button("Generar Hash (scrypt)", key="generate_scrypt_hash_button"):
        if scrypt_password:
            with st.spinner("Generando hash scrypt..."):
                try:
                    # Generate a random salt for scrypt
                    scrypt_salt = get_random_bytes(16)
                    hashed_password = hashlib.scrypt(
                        scrypt_password.encode('utf-8'), 
                        salt=scrypt_salt, 
                        n=scrypt_n, 
                        r=scrypt_r, 
                        p=scrypt_p, 
                        dklen=scrypt_dklen
                    )
                    st.success(f"Hash scrypt generado (Hex): `{hashed_password.hex()}`")
                    st.write(f"Salt utilizado (Hex): `{scrypt_salt.hex()}`")
                    create_download_button("Descargar Hash scrypt (Hex)", hashed_password.hex().encode('utf-8'), "scrypt_hash.txt", "text/plain")
                    create_download_button("Descargar Salt scrypt (Hex)", scrypt_salt.hex().encode('utf-8'), "scrypt_salt.txt", "text/plain")
                except Exception as e:
                    st.error(f"Error al generar hash scrypt: {e}")
        else:
            st.warning("Por favor, ingrese una contraseña para scrypt.")

    if st.button("Limpiar Contraseña scrypt", on_click=clear_scrypt_password, key="clear_scrypt_password_button"):
        pass

    st.markdown("---")
    st.markdown("##### Argon2")
    st.write("Argon2 es la KDF ganadora del concurso Password Hashing Competition (PHC). Ofrece una alta configurabilidad en términos de tiempo, memoria y paralelismo, lo que la hace muy flexible y robusta contra diversos tipos de ataques, incluyendo ataques de fuerza bruta y ataques con hardware especializado.")
    
    if PasswordHasher: # Only show if Argon2 is imported successfully
        # Initialize session state for Argon2 password input if it doesn't exist
        if 'argon2_password_value' not in st.session_state:
            st.session_state.argon2_password_value = ""

        # Callback function to clear the Argon2 password input
        def clear_argon2_password():
            st.session_state.argon2_password_value = ""

        argon2_password = st.text_input(
            "Ingrese la contraseña (Argon2):",
            type="password",
            key="argon2_password_widget",
            value=st.session_state.argon2_password_value,
            on_change=lambda: st.session_state.update(argon2_password_value=st.session_state.argon2_password_widget)
        )
        argon2_time_cost = st.number_input("Costo de tiempo (iteraciones):", min_value=1, value=3, step=1, key="argon2_time_cost_input")
        argon2_memory_cost = st.number_input("Costo de memoria (KiB):", min_value=8, value=65536, step=1024, key="argon2_memory_cost_input")
        argon2_parallelism = st.number_input("Paralelismo (hilos/CPU):", min_value=1, value=4, step=1, key="argon2_parallelism_input")

        if st.button("Generar Hash (Argon2)", key="generate_argon2_hash_button"):
            if argon2_password:
                with st.spinner("Generando hash Argon2..."):
                    try:
                        ph = PasswordHasher(
                            time_cost=argon2_time_cost,
                            memory_cost=argon2_memory_cost,
                            parallelism=argon2_parallelism,
                            hash_len=32 # Longitud del hash en bytes
                        )
                        hashed_password = ph.hash(argon2_password)
                        st.success(f"Hash Argon2 generado: `{hashed_password}`")
                        create_download_button("Descargar Hash Argon2", hashed_password.encode('utf-8'), "argon2_hash.txt", "text/plain")
                    except argon2_exceptions.InvalidHashError as e:
                        st.error(f"Error de hash Argon2 inválido: {e}")
                    except Exception as e:
                        st.error(f"Error al generar hash Argon2: {e}")
            else:
                st.warning("Por favor, ingrese una contraseña para Argon2.")
        
        if st.button("Limpiar Contraseña Argon2", on_click=clear_argon2_password, key="clear_argon2_password_button"):
            pass
    else:
        st.info("*(La implementación de Argon2 requiere la librería `argon2-cffi`.)*")


# --- 5. Función Hash ---
with st.expander("5. Función Hash", expanded=False): # Changed title to be more general
    st.markdown("#### Generación y Demostración de Funciones Hash") # Changed title
    st.info("Una función hash criptográfica toma una entrada (o 'mensaje') y devuelve una cadena de bytes de tamaño fijo, que es el 'valor hash'. Es una función unidireccional (irreversible) y colisión-resistente, ideal para verificar la integridad de los datos.")
    
    hash_algorithm_select = st.selectbox(
        "Seleccione el algoritmo de hash:",
        ("SHA-256", "SHA-512", "SHA-3 (Keccak)", "BLAKE2b", "MD5 (No recomendado para seguridad)"),
        key="hash_algorithm_select"
    )
    hash_data_input = st.text_area("Ingrese el texto a hashear:", "Integridad de datos criptografica", height=100, key="hash_data_input")
    hash_data_modified_input = st.text_area("Ingrese el texto ligeramente modificado (para efecto avalancha):", "Integridad de datos criptograficax", height=100, key="hash_data_modified_input")

    if st.button("Generar Hashes y Demostrar Efecto Avalancha", key="generate_hash_button"):
        if hash_data_input:
            with st.spinner("Generando Hashes..."):
                try:
                    data_bytes = hash_data_input.encode('utf-8')
                    hash_value = ""
                    
                    if hash_algorithm_select == "SHA-256":
                        hash_value = hashlib.sha256(data_bytes).hexdigest()
                    elif hash_algorithm_select == "SHA-512":
                        hash_value = hashlib.sha512(data_bytes).hexdigest()
                    elif hash_algorithm_select == "SHA-3 (Keccak)":
                        hash_value = hashlib.sha3_256(data_bytes).hexdigest() # Using sha3_256 for demonstration
                    elif hash_algorithm_select == "BLAKE2b":
                        hash_value = hashlib.blake2b(data_bytes).hexdigest()
                    elif hash_algorithm_select == "MD5 (No recomendado para seguridad)":
                        hash_value = hashlib.md5(data_bytes).hexdigest()
                    
                    st.write(f"**Texto original:** `{hash_data_input}`")
                    st.success(f"**Hash {hash_algorithm_select}:** `{hash_value}`")
                    create_download_button(f"Descargar Hash {hash_algorithm_select}", hash_value.encode('utf-8'), f"hash_{hash_algorithm_select.lower().replace(' ', '_').replace('(', '').replace(')', '')}.txt", "text/plain")

                    if hash_data_modified_input: # Check if modified input is provided
                        modified_data_bytes = hash_data_modified_input.encode('utf-8')
                        modified_hash_value = ""
                        if hash_algorithm_select == "SHA-256":
                            modified_hash_value = hashlib.sha256(modified_data_bytes).hexdigest()
                        elif hash_algorithm_select == "SHA-512":
                            modified_hash_value = hashlib.sha512(modified_data_bytes).hexdigest()
                        elif hash_algorithm_select == "SHA-3 (Keccak)":
                            modified_hash_value = hashlib.sha3_256(modified_data_bytes).hexdigest()
                        elif hash_algorithm_select == "BLAKE2b":
                            modified_hash_value = hashlib.blake2b(modified_data_bytes).hexdigest()
                        elif hash_algorithm_select == "MD5 (No recomendado para seguridad)":
                            modified_hash_value = hashlib.md5(modified_data_bytes).hexdigest()

                        st.write(f"**Texto modificado:** `{hash_data_modified_input}`") 
                        st.info(f"**Hash {hash_algorithm_select} modificado:** `{modified_hash_value}`")
                        st.markdown("---")
                        st.markdown("#### Efecto Avalancha:")
                        st.info("Observe cómo un pequeño cambio en el texto original produce un hash completamente diferente. Esto es una característica deseable de las funciones hash criptográficas.")
                        
                        # Visualización simple de la diferencia
                        diff_count = sum(c1 != c2 for c1, c2 in zip(hash_value, modified_hash_value))
                        st.write(f"Número de caracteres diferentes entre los hashes: {diff_count} de {len(hash_value)}")
                    
                    st.markdown("---")
                    st.markdown("*(Nota sobre BLAKE3: BLAKE3 no está disponible directamente en la librería `hashlib` de Python y requeriría una instalación separada de `pyblake3` para su implementación.)*")


                except Exception as e:
                    st.error(f"Error al generar el hash: {e}")
        else:
            st.warning("Por favor, ingrese un texto para hashear.")

# --- 6. Generar Números Pseudoaleatorios (CSPRNG) ---
with st.expander("6. Generar Números Pseudoaleatorios (CSPRNG)", expanded=False):
    st.markdown("#### Generador de Números Pseudoaleatorios Criptográficamente Seguros (CSPRNG)")
    st.info("Estos números son generados por un Generador de Números Pseudoaleatorios Criptográficamente Seguro (CSPRNG), lo que los hace adecuados para usos criptográficos donde la impredecibilidad es crucial.")
    
    prng_count = st.number_input("Cantidad de números a generar:", min_value=1, value=10, step=1, key="prng_count_input_unique") 
    prng_min_val = st.number_input("Valor mínimo (inclusive):", value=0, step=1, key="prng_min_val_input_unique") 
    prng_max_val = st.number_input("Valor máximo (inclusive):", value=100, step=1, key="prng_max_val_input_unique") 

    if st.button("Generar Números Pseudoaleatorios", key="generate_prng_button_unique"): 
        if prng_min_val >= prng_max_val:
            st.error("El valor mínimo debe ser menor que el valor máximo.")
        else:
            with st.spinner("Generando números..."):
                try:
                    random_numbers = [secrets.randbelow(prng_max_val - prng_min_val + 1) + prng_min_val for _ in range(prng_count)] # Usando secrets.randbelow
                    st.success(f"Números pseudoaleatorios generados: `{random_numbers}`")
                    create_download_button("Descargar Números", str(random_numbers).encode('utf-8'), "pseudo_random_numbers.txt", "text/plain")
                except Exception as e:
                    st.error(f"Error al generar números pseudoaleatorios: {e}")

# --- 7. Cifrado y Descifrado AES (CBC) ---
with st.expander("7. Cifrado y Descifrado AES (CBC)", expanded=False):
    st.markdown("#### Cifrado y Descifrado con AES en Modo CBC")
    st.info("AES (Advanced Encryption Standard) es un algoritmo de cifrado por bloques ampliamente utilizado. El modo CBC (Cipher Block Chaining) añade seguridad encadenando el cifrado de cada bloque con el anterior, usando un IV para el primer bloque.")
    
    aes_full_plaintext_input = st.text_area("Ingrese el texto claro para cifrar/descifrar:", "Este es un mensaje secreto para cifrar con AES.", height=100, key="aes_full_plaintext_input")
    
    if st.button("Cifrar y Descifrar AES", key="aes_full_process_button"):
        if aes_full_plaintext_input:
            with st.spinner("Realizando cifrado y descifrado AES..."):
                try:
                    # Generate a new key and IV for this operation
                    aes_key = get_random_bytes(16) # AES-128 key
                    aes_iv = get_random_bytes(16)  # 16-byte IV for CBC

                    st.subheader("Proceso de Cifrado")
                    st.write(f"**Texto Claro Original:** `{aes_full_plaintext_input}`")
                    st.write(f"**Clave AES (Hex):** `{aes_key.hex()}`")
                    st.write(f"**IV AES (Hex):** `{aes_iv.hex()}`")

                    # Encryption
                    cipher_encrypt = AES.new(aes_key, AES.MODE_CBC, aes_iv)
                    plaintext_bytes = aes_full_plaintext_input.encode('utf-8')
                    padded_plaintext = pad(plaintext_bytes, AES.block_size)
                    ciphertext_bytes = cipher_encrypt.encrypt(padded_plaintext)
                    
                    st.success(f"**Texto Cifrado (Hex):** `{ciphertext_bytes.hex()}`")
                    create_download_button("Descargar Texto Cifrado AES (Hex)", ciphertext_bytes.hex().encode('utf-8'), "aes_full_ciphertext.txt", "text/plain")

                    st.subheader("Proceso de Descifrado")
                    # Decryption
                    cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, aes_iv) # Must use same key and IV
                    decrypted_padded_bytes = cipher_decrypt.decrypt(ciphertext_bytes)
                    decrypted_plaintext = unpad(decrypted_padded_bytes, AES.block_size).decode('utf-8')
                    
                    st.info(f"**Texto Descifrado:** `{decrypted_plaintext}`")
                    
                    if decrypted_plaintext == aes_full_plaintext_input:
                        st.success("✅ ¡Cifrado y descifrado exitosos! El texto original se recuperó correctamente.")
                    else:
                        st.error("❌ Error: El texto descifrado no coincide con el original.")
                    
                    # Visualization of bytes
                    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 12))

                    # Original Plaintext
                    ax1.bar(range(len(plaintext_bytes)), [b for b in plaintext_bytes], color='skyblue')
                    ax1.set_title("Texto Claro Original (Bytes)")
                    ax1.set_xlabel("Posición del Byte")
                    ax1.set_ylabel("Valor")
                    ax1.set_ylim(0, 255)

                    # Ciphertext
                    ax2.bar(range(len(ciphertext_bytes)), [b for b in ciphertext_bytes], color='lightcoral')
                    ax2.set_title("Texto Cifrado (Bytes)")
                    ax2.set_xlabel("Posición del Byte")
                    ax2.set_ylabel("Valor")
                    ax2.set_ylim(0, 255)

                    # Decrypted Plaintext
                    ax3.bar(range(len(decrypted_padded_bytes)), [b for b in decrypted_padded_bytes], color='lightgreen')
                    ax3.set_title("Texto Descifrado (Bytes)")
                    ax3.set_xlabel("Posición del Byte")
                    ax3.set_ylabel("Valor")
                    ax3.set_ylim(0, 255)
                    
                    plt.tight_layout()
                    st.pyplot(fig)
                    plt.close(fig)

                except Exception as e:
                    st.error(f"Error durante el cifrado/descifrado AES: {e}")
        else:
            st.warning("Por favor, ingrese un texto claro para cifrar.")

# --- 8. Visualizar Proceso de Cifrado (Básico) ---
with st.expander("8. Visualizar Proceso de Cifrado (Básico)", expanded=False):
    st.markdown("#### Visualización Simplificada del Proceso de Cifrado AES-CBC")
    st.info("Esta visualización muestra una representación abstracta de cómo el texto claro se transforma en texto cifrado. No representa los valores exactos de los bytes, sino una comparación visual de sus 'magnitudes'.")
    
    viz_plaintext_input = st.text_area("Ingrese el texto para visualizar el cifrado:", "Hola Mundo Criptografia", key="viz_plaintext_input")

    if st.button("Visualizar Cifrado", key="visualize_encryption_button"):
        if viz_plaintext_input:
            with st.spinner("Generando visualización..."):
                try:
                    key = secrets.token_bytes(16) # Usando secrets.token_bytes
                    iv = secrets.token_bytes(16) # Usando secrets.token_bytes
                    cipher = AES.new(key, AES.MODE_CBC, iv)

                    plaintext_bytes = viz_plaintext_input.encode('utf-8')
                    padded_plaintext = pad(plaintext_bytes, AES.block_size)
                    ciphertext = cipher.encrypt(padded_plaintext)

                    fig, ax = plt.subplots(figsize=(10, 5))
                    
                    # Plot plaintext bytes
                    ax.bar(range(len(plaintext_bytes)), [b for b in plaintext_bytes], color='skyblue', label="Texto Claro (bytes)")
                    # Plot ciphertext bytes (ensure same length for plotting, though actual content differs)
                    ax.bar(range(len(ciphertext)), [b for b in ciphertext], color='lightcoral', label="Texto Cifrado (bytes)", alpha=0.7)
                    
                    ax.set_title("Transformación de Texto Claro a Cifrado (AES-CBC)")
                    ax.set_xlabel("Posición del Byte")
                    ax.set_ylabel("Valor del Byte (0-255)")
                    ax.legend()
                    ax.grid(axis='y', linestyle='--')
                    
                    st.pyplot(fig) # Display the plot in Streamlit
                    plt.close(fig) # Close the figure to free memory
                except Exception as e:
                    st.error(f"Error al visualizar el cifrado: {e}")
        else:
            st.warning("Por favor, ingrese un texto para visualizar.")

st.markdown("---")
st.markdown("Una herramienta de ciberseguridad para fines educativos y demostrativos.")
