from nacl.secret import SecretBox
from nacl.utils import random


def xor_bytes(a, b):
    """
    XOR hai dãy bytes có cùng độ dài.
    """

    if len(a) != len(b):
        raise ValueError("Hai dữ liệu phải có cùng độ dài.")

    return bytes(x ^ y for x, y in zip(a, b))


def generate_pad(key, nonce, size):
    """
    Sinh size bytes pseudorandom pad.

    SecretBox.encrypt(bytes(size), nonce) tạo:

        16-byte authentication tag
        +
        size-byte encrypted data

    Vì:

        0 XOR pad = pad

    nên bỏ 16-byte tag để lấy pad.
    """

    box = SecretBox(key)

    encrypted = box.encrypt(bytes(size), nonce)

    # Bỏ 16-byte authentication tag
    return encrypted.ciphertext[16:]


# ============================================================
# TASK 3 STREAM CIPHER
# ============================================================

def encrypt(key, nonce, message):
    """
    Stream cipher:

        C = M XOR G(key, nonce)
    """

    pad = generate_pad(key, nonce, len(message))

    return xor_bytes(message, pad)


def decrypt(key, nonce, ciphertext):
    """
    Stream cipher:

        M = C XOR G(key, nonce)
    """

    pad = generate_pad(key, nonce, len(ciphertext))

    return xor_bytes(ciphertext, pad)


def print_hex(label, data):
    print(f"{label}:")
    print(data.hex())
    print()


# ============================================================
# PHẦN 1 - TẤN CÔNG STREAM CIPHER
# ============================================================

def task5_stream_cipher_attack():

    print("=" * 70)
    print("PART 1 - STREAM CIPHER ATTACK")
    print("=" * 70)

    # --------------------------------------------------------
    # Message gốc
    # --------------------------------------------------------

    original_message = b"PAY BOB 0100 USD"
    target_message = b"PAY BOB 9900 USD"

    print("\n[1] PLAINTEXT")

    print("Original:", original_message)
    print("Target  :", target_message)

    # --------------------------------------------------------
    # Kiểm tra độ dài
    # --------------------------------------------------------

    if len(original_message) != len(target_message):
        raise ValueError(
            "Original và target phải có cùng độ dài."
        )

    print(
        "Length:",
        len(original_message),
        "bytes"
    )

    # --------------------------------------------------------
    # Tạo key và nonce
    # --------------------------------------------------------

    key = random(32)
    nonce = random(24)

    print("\n[2] KEY AND NONCE")

    print("Key   :", key.hex())
    print("Nonce :", nonce.hex())

    # --------------------------------------------------------
    # Encrypt message gốc
    # --------------------------------------------------------

    ciphertext = encrypt(
        key,
        nonce,
        original_message
    )

    print("\n[3] ORIGINAL CIPHERTEXT")

    print_hex(
        "Ciphertext",
        ciphertext
    )

    # --------------------------------------------------------
    # Kiểm tra decrypt bình thường
    # --------------------------------------------------------

    decrypted_original = decrypt(key, nonce, ciphertext)

    print(
        "Normal decryption:",
        decrypted_original
    )

    # --------------------------------------------------------
    # ATTACK: delta = M XOR M'
    # --------------------------------------------------------

    print("\n[4] CALCULATING DELTA")

    delta = xor_bytes(original_message, target_message)

    print_hex(
        "Delta = Original XOR Target",
        delta
    )

    # --------------------------------------------------------
    # Forge ciphertext: C' = C XOR Delta
    # --------------------------------------------------------

    print("\n[5] FORGING CIPHERTEXT")

    forged_ciphertext = xor_bytes(ciphertext, delta)

    print_hex(
        "Forged ciphertext",
        forged_ciphertext
    )

    # --------------------------------------------------------
    # Decrypt forged ciphertext
    # --------------------------------------------------------

    forged_decryption = decrypt(key, nonce, forged_ciphertext)

    print("[6] DECRYPTING FORGED CIPHERTEXT")

    print(
        "Forged decryption:",
        forged_decryption
    )

    print(
        "Attack successful:",
        forged_decryption == target_message
    )


    print()
    print(
        "The forged ciphertext decrypts to:",
        forged_decryption
    )

    return (
        key,
        nonce,
        original_message,
        target_message,
        ciphertext,
        forged_ciphertext,
        delta
    )


# ============================================================
# PHẦN 2 - TẤN CÔNG SECRETBOX
# ============================================================

def task5_secretbox_attack(
    key,
    original_message,
    target_message,
    delta
):

    print("\n")
    print("=" * 70)
    print("PART 2 - SECRETBOX ATTACK")
    print("=" * 70)

    # --------------------------------------------------------
    # Tạo SecretBox
    # --------------------------------------------------------

    box = SecretBox(key)

    # --------------------------------------------------------
    # Encrypt message bằng SecretBox
    # --------------------------------------------------------

    encrypted = box.encrypt(original_message)

    print("\n[1] SECRETBOX ENCRYPTION")

    print("Original message:")
    print(original_message)

    print()

    print(
        "Full SecretBox output:",encrypted.hex()
    )

    # --------------------------------------------------------
    # Tách tag và body
    # --------------------------------------------------------

    nonce = encrypted.nonce
    secretbox_ciphertext = encrypted.ciphertext

    tag = secretbox_ciphertext[:16]
    body = secretbox_ciphertext[16:]

    print("\n[2] SECRETBOX LAYOUT")

    print("Nonce:")
    print(nonce.hex())

    print()
    print("Nonce length:", len(nonce), "bytes")

    print()
    print("Tag:")
    print(tag.hex())

    print()
    print("Tag length:", len(tag), "bytes")

    print()
    print("Encrypted body:")
    print(body.hex())

    print()
    print("Body length:", len(body), "bytes")

    # --------------------------------------------------------
    # Decrypt bình thường
    # --------------------------------------------------------

    print("\n[3] SECRETBOX DECRYPTION")

    normal_decryption = box.decrypt(encrypted)

    print(
        "Decrypted:", normal_decryption
    )

    # --------------------------------------------------------
    # Sửa encrypted body: body' = body XOR delta
    # --------------------------------------------------------

    print("\n[4] MODIFYING THE ENCRYPTED BODY")

    forged_body = xor_bytes(body,delta)

    print("Original body:")
    print(body.hex())

    print()

    print("Forged body:")
    print(forged_body.hex())

    # --------------------------------------------------------
    # Gắn lại tag cũ ta được [ TAG CŨ ][ BODY ĐÃ BỊ SỬA ]
    # --------------------------------------------------------

    forged_secretbox_ciphertext = (
        tag + forged_body
    )

    forged_full_ciphertext = (
        nonce + forged_secretbox_ciphertext
    )

    print("\n[5] FORGED SECRETBOX CIPHERTEXT")

    print(
        forged_full_ciphertext.hex()
    )

    # --------------------------------------------------------
    # Thử decrypt
    # --------------------------------------------------------

    print("\n[6] TRYING TO DECRYPT FORGED CIPHERTEXT")

    try:

        result = box.decrypt(
            forged_full_ciphertext
        )

        print("Decryption succeeded:")
        print(result)

        print(
            "\nWARNING:",
            "SecretBox accepted the modified ciphertext."
        )

    except Exception as error:

        print(
            "Decryption failed."
        )

        print(
            "Exception type:",
            type(error).__name__
        )

        print(
            "Error:",
            error
        )

        print(
            "\nAuthentication tag detected that the "
            "ciphertext was modified."
        )


def main():

    print("=" * 70)
    print("TASK 5 - CHANGING AN ENCRYPTED AMOUNT")
    print("=" * 70)

    # --------------------------------------------------------
    # PART 1 - Stream cipher
    # --------------------------------------------------------

    (
        key,
        nonce,
        original_message,
        target_message,
        ciphertext,
        forged_ciphertext,
        delta
    ) = task5_stream_cipher_attack()

    # --------------------------------------------------------
    # PART 2 - SecretBox
    # --------------------------------------------------------

    task5_secretbox_attack(
        key,
        original_message,
        target_message,
        delta
    )

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("TASK 5 COMPLETED")
    print("=" * 70)

    print()
    print("Part 1:")
    print(
        "Raw stream cipher accepted the forged ciphertext."
    )

    print()
    print("Original plaintext:")
    print(original_message)

    print()
    print("Target plaintext:")
    print(target_message)

    print()
    print("Part 2:")
    print(
        "SecretBox rejected the modified ciphertext "
        "because the authentication tag no longer matches."
    )

    print()
    print("Key lesson:")
    print(
        "Encryption alone provides confidentiality, "
        "but authentication is needed to detect modification."
    )

if __name__ == "__main__":
    main()