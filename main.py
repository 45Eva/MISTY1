from misty1 import EncryptBlock, DecryptBlock

def main():
    # === ПЕРЕВІРКА ШИФРУВАННЯ ТА РОЗШИФРУВАННЯ ===
    key_hex = "414afd99bb577ee69df58cc8fb4e6888"
    pt_hex  = "9fc302e281310e90"
    ct_hex  = "15c270974b9b9163"

    key = bytes.fromhex(key_hex)
    P   = bytes.fromhex(pt_hex)
    C_exp = bytes.fromhex(ct_hex)

    print("K  =", key_hex)
    print("P  =", pt_hex)

    # --- ШИФРУВАННЯ ---
    C = EncryptBlock(P, key)
    print("\n[Encrypt]")
    print("C  =", C.hex())
    print("Оч =", ct_hex)
    print("Збіг?", C == C_exp)

    # --- РОЗШИФРУВАННЯ ---
    P2 = DecryptBlock(C, key)
    print("\n[Decrypt]")
    print("P' =", P2.hex())
    print("Оч =", pt_hex)
    print("Збіг?", P2 == P)


if __name__ == "__main__":
    main()
