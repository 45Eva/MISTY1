import argparse
import sys
from pathlib import Path
from typing import Union

from misty1 import EncryptBlock, DecryptBlock


# ---------------------------------------------
# Налаштування для MISTY1
# ---------------------------------------------
BLOCK_SIZE = 8          # 64 біти = 8 байтів
DEFAULT_KEY_FILE = "key.txt"   # ключ завжди тут (за замовчуванням)


# ---------------------------------------------
# Читання ключа з файлу key.txt
# ---------------------------------------------
def read_key_hex_file(key_path: Union[str, Path]) -> str:
    key_path = Path(key_path)

    if not key_path.exists():
        raise FileNotFoundError(f"Файл ключа не знайдено: {key_path}")

    text = key_path.read_text(encoding="utf-8").strip()

    # прибираємо зайве, щоб було зручно
    text = text.lower().replace("0x", "").replace(" ", "").replace("\n", "").replace("\r", "")

    # перевірка довжини (128 біт = 32 hex-символи)
    if len(text) != 32:
        raise ValueError("key.txt: ключ має бути 32 hex-символи (128 біт).")

    # перевірка, що це hex
    int(text, 16)

    return text


# ---------------------------------------------
# EncryptData / DecryptData (ECB режим)
# ---------------------------------------------

def EncryptData(data: bytes, key128: Union[int, bytes, str]) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("EncryptData: data має бути bytes або bytearray")

    padded = bytes(data)

    # доповнення нулями до кратності 8
    pad_len = (-len(padded)) % BLOCK_SIZE
    if pad_len != 0:
        padded += b"\x00" * pad_len

    # шифрування блоками
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        out += EncryptBlock(block, key128)

    return bytes(out)



def DecryptData(ciphertext: bytes, key128: Union[int, bytes, str]) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("DecryptData: ciphertext має бути bytes або bytearray")

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("DecryptData: довжина ciphertext не кратна 8 байтам (ECB).")

    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        out += DecryptBlock(block, key128)

    return bytes(out)


# ---------------------------------------------
# Робота з файлами (encrypt/decrypt file)
# ---------------------------------------------

def encrypt_file(input_path: Union[str, Path], output_path: Union[str, Path], key_path: Union[str, Path] = DEFAULT_KEY_FILE) -> None:
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(f"Вхідний файл не знайдено: {input_path}")

    key_hex = read_key_hex_file(key_path)
    data = input_path.read_bytes()
    orig_len = len(data)

    ciphertext = EncryptData(data, key_hex)

    header = orig_len.to_bytes(8, byteorder="big", signed=False)
    output_path.write_bytes(header + ciphertext)



def decrypt_file(input_path: Union[str, Path], output_path: Union[str, Path], key_path: Union[str, Path] = DEFAULT_KEY_FILE) -> None:
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(f"Вхідний файл не знайдено: {input_path}")

    key_hex = read_key_hex_file(key_path)
    blob = input_path.read_bytes()

    if len(blob) < 8:
        raise ValueError("cipher file: файл занадто короткий, немає заголовка 8 байтів.")

    orig_len = int.from_bytes(blob[:8], byteorder="big", signed=False)
    ciphertext = blob[8:]

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("cipher file: довжина ciphertext не кратна 8 (ECB).")

    plaintext_padded = DecryptData(ciphertext, key_hex)

    if orig_len > len(plaintext_padded):
        raise ValueError("cipher file: некоректний заголовок orig_len (більший за розшифровані дані).")

    plaintext = plaintext_padded[:orig_len]
    output_path.write_bytes(plaintext)


# ---------------------------------------------
# Інтерактивний інтерфейс (меню)
# ---------------------------------------------

#safe_input:

def safe_input(prompt: str) -> str:
    while True:
        s = input(prompt).strip()
        if s:
            return s
        print("Будь ласка, введіть непорожнє значення.")



# interactive_menu:

def interactive_menu() -> int:
    print("Вітаю! Це утиліта MISTY1 (ECB) для шифрування/розшифрування файлів.")
    print(f"Файл ключа використовується за замовчуванням: {DEFAULT_KEY_FILE}")
    print("-" * 65)

    while True:
        print("\nОберіть дію:")
        print("  1 — Зашифрувати файл")
        print("  2 — Розшифрувати файл")
        print("  0 — Вийти")

        choice = input("Ваш вибір: ").strip()

        if choice == "0":
            print("Вихід з програми.")
            return 0

        if choice == "1":
            inp = safe_input("Введіть назву (шлях) файлу, який треба зашифрувати: ")
            out = safe_input("Введіть назву (шлях) файлу, куди записати шифротекст: ")

            try:
                encrypt_file(inp, out, DEFAULT_KEY_FILE)
                print(f"[OK] Зашифровано: {inp} -> {out}")
            except Exception as e:
                print(f"[ERROR] {e}")
            continue

        if choice == "2":
            inp = safe_input("Введіть назву (шлях) файлу, який треба розшифрувати: ")
            out = safe_input("Введіть назву (шлях) файлу, куди записати розшифрований текст: ")

            try:
                decrypt_file(inp, out, DEFAULT_KEY_FILE)
                print(f"[OK] Розшифровано: {inp} -> {out}")
            except Exception as e:
                print(f"[ERROR] {e}")
            continue

        print("Невірний вибір. Введіть 1, 2 або 0.")


# ---------------------------------------------
# CLI (залишаємо як запасний варіант)
# ---------------------------------------------
"""
Приклади CLI:
python main.py encrypt -i plain-text.txt -o cipher-text.bin
python main.py decrypt -i cipher-text.bin -o decrypt-text.txt

Ключ не передаємо — він береться з key.txt автоматично.
"""
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MISTY1 file encryptor/decryptor (ECB mode)"
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Зашифрувати файл")
    enc.add_argument("-i", "--in", dest="inp", required=True, help="вхідний файл (plain-text)")
    enc.add_argument("-o", "--out", dest="out", required=True, help="вихідний файл (cipher-text)")

    dec = sub.add_parser("decrypt", help="Розшифрувати файл")
    dec.add_argument("-i", "--in", dest="inp", required=True, help="вхідний файл (cipher-text)")
    dec.add_argument("-o", "--out", dest="out", required=True, help="вихідний файл (decrypt-text)")

    return parser


def main() -> int:
    # Якщо запуск без аргументів: python main.py
    # то працюємо у форматі меню 
    if len(sys.argv) == 1:
        return interactive_menu()

    # Якщо аргументи є — працюємо як CLI.
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.cmd == "encrypt":
            encrypt_file(args.inp, args.out, DEFAULT_KEY_FILE)
            print(f"[OK] Зашифровано: {args.inp} -> {args.out}")
            return 0

        if args.cmd == "decrypt":
            decrypt_file(args.inp, args.out, DEFAULT_KEY_FILE)
            print(f"[OK] Розшифровано: {args.inp} -> {args.out}")
            return 0

        print("[ERROR] Невідома команда")
        return 2

    except Exception as e:
        print(f"[ERROR] {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
