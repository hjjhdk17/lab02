import hashlib
import time

from nacl.secret import SecretBox
from nacl.utils import random


# ============================================================
# CẤU HÌNH
# ============================================================

CHUNK_SIZE = 1024 * 1024       # 1 MiB
KEY_SIZE = 32                  # 32 bytes = 256 bits
PREFIX_SIZE = 16               # 16 bytes
NONCE_SIZE = 24                # 16-byte prefix + 8-byte counter

INPUT_FILE = "book.pdf"
ENCRYPTED_FILE = "book.enc"
DECRYPTED_FILE = "book.dec.pdf"

BUGGY_ENCRYPTED_FILE = "book_buggy.enc"


# ============================================================
# HÀM XOR
# ============================================================

def xor_bytes(a, b):
    """
    XOR hai dãy bytes có cùng độ dài.
    """

    if len(a) != len(b):
        raise ValueError("Hai dữ liệu phải có cùng độ dài.")

    return bytes(x ^ y for x, y in zip(a, b))


# ============================================================
# HÀM SINH PAD G(key, nonce, n)
# ============================================================

def generate_pad(key, nonce, size):
    """
    Sinh 'size' bytes pseudorandom pad bằng SecretBox.

    SecretBox.encrypt(bytes(size), nonce) tạo ra:
        16-byte authentication tag || size-byte ciphertext

    Vì:
        0 XOR pad = pad

    nên bỏ 16-byte tag để lấy phần pad.
    """

    box = SecretBox(key)

    encrypted = box.encrypt(bytes(size), nonce)

    # Bỏ 16-byte authentication tag
    pad = encrypted.ciphertext[16:]

    return pad


# ============================================================
# TẠO NONCE
# ============================================================

def make_nonce(prefix, counter):
    """
    Tạo nonce = prefix || counter

    prefix:
        16 bytes

    counter:
        8 bytes

    Tổng:
        24 bytes
    """

    if len(prefix) != PREFIX_SIZE:
        raise ValueError("Prefix phải dài 16 bytes.")

    counter_bytes = counter.to_bytes(8, "little")

    nonce = prefix + counter_bytes

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce phải dài 24 bytes.")

    return nonce


# ============================================================
# SHA-256 CỦA FILE
# ============================================================

def sha256_file(filename):
    """
    Tính SHA-256 của một file theo từng chunk.
    """

    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# MÃ HÓA BOOK.PDF
# ============================================================

def encrypt_book(input_file, output_file, key):
    """
    Mã hóa book.pdf thành book.enc.

    Cấu trúc book.enc:

        prefix (16 bytes)
        ciphertext chunk 0
        ciphertext chunk 1
        ciphertext chunk 2
        ...

    Chunk i sử dụng:

        nonce = prefix || i
    """

    # Prefix ngẫu nhiên dùng chung cho file
    prefix = random(PREFIX_SIZE)

    print("Prefix:", prefix.hex())

    start_time = time.perf_counter()

    total_plaintext = 0
    total_ciphertext = 0
    counter = 0

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:

        # Ghi prefix vào đầu file encrypted
        fout.write(prefix)

        while True:

            # Đọc tối đa 1 MiB
            plaintext = fin.read(CHUNK_SIZE)

            # Đã đọc hết file
            if not plaintext:
                break

            # Tạo nonce cho chunk hiện tại
            nonce = make_nonce(prefix, counter)

            # Sinh pad có cùng độ dài với plaintext
            pad = generate_pad(key, nonce, len(plaintext))

            # C = M XOR pad
            ciphertext = xor_bytes(plaintext, pad)

            # Ghi ciphertext
            fout.write(ciphertext)

            total_plaintext += len(plaintext)
            total_ciphertext += len(ciphertext)

            counter += 1

    elapsed = time.perf_counter() - start_time

    return prefix, total_plaintext, total_ciphertext, counter, elapsed


# ============================================================
# GIẢI MÃ BOOK.ENC
# ============================================================

def decrypt_book(input_file, output_file, key):
    """
    Giải mã book.enc thành book.dec.pdf.
    """

    total_ciphertext = 0
    total_plaintext = 0
    counter = 0

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:

        # Đọc 16-byte prefix ở đầu file
        prefix = fin.read(PREFIX_SIZE)

        if len(prefix) != PREFIX_SIZE:
            raise ValueError("File encrypted không chứa đủ 16-byte prefix.")

        while True:

            # Đọc ciphertext chunk
            ciphertext = fin.read(CHUNK_SIZE)

            if not ciphertext:
                break

            # Tạo đúng nonce mà lúc encrypt đã sử dụng
            nonce = make_nonce(prefix, counter)

            # Sinh lại đúng pad
            pad = generate_pad(key, nonce, len(ciphertext))

            # M = C XOR pad
            plaintext = xor_bytes(ciphertext, pad)

            # Ghi plaintext ra file PDF
            fout.write(plaintext)

            total_ciphertext += len(ciphertext)
            total_plaintext += len(plaintext)

            counter += 1

    return prefix, total_ciphertext, total_plaintext, counter


# ============================================================
# LẤY 16 BYTE ĐẦU CỦA FILE
# ============================================================

def read_first_bytes(filename, size):
    """
    Đọc size bytes đầu tiên của file.
    """

    with open(filename, "rb") as file:
        return file.read(size)


def read_first_ciphertext_bytes(filename, size):
    """
    Đọc size bytes ciphertext đầu tiên.

    book.enc có cấu trúc:

        [16-byte prefix][ciphertext...]

    nên phải bỏ qua prefix trước.
    """

    with open(filename, "rb") as file:

        # Bỏ qua prefix
        prefix = file.read(PREFIX_SIZE)

        if len(prefix) != PREFIX_SIZE:
            raise ValueError("Không đọc đủ prefix.")

        return file.read(size)


# ============================================================
# MÃ HÓA BUGGY:
# FORGOTTEN-COUNTER
# ============================================================

def encrypt_book_buggy(input_file, output_file, key, prefix):
    """
    Phiên bản cố tình bị lỗi.

    ĐÚNG:

        nonce = prefix || counter

    BUGGY:

        nonce = prefix || 0

    Vì vậy tất cả chunk sử dụng cùng một nonce
    và cùng một keystream.
    """

    total_plaintext = 0
    total_ciphertext = 0
    counter = 0

    # Counter luôn bị cố định bằng 0
    forgotten_counter = 0

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:

        # Ghi prefix
        fout.write(prefix)

        while True:

            plaintext = fin.read(CHUNK_SIZE)

            if not plaintext:
                break

            # BUG:
            # chunk nào cũng dùng prefix || 0
            nonce = make_nonce(prefix, forgotten_counter)

            pad = generate_pad(key, nonce, len(plaintext))

            ciphertext = xor_bytes(plaintext, pad)

            fout.write(ciphertext)

            total_plaintext += len(plaintext)
            total_ciphertext += len(ciphertext)

            counter += 1

    return total_plaintext, total_ciphertext, counter


# ============================================================
# LẤY CHUNK ĐẦU TIÊN CỦA FILE
# ============================================================

def read_first_two_chunks(filename):
    """
    Đọc hai chunk đầu tiên của file plaintext/ciphertext.

    Mỗi chunk tối đa 1 MiB.
    """

    with open(filename, "rb") as file:

        chunk0 = file.read(CHUNK_SIZE)
        chunk1 = file.read(CHUNK_SIZE)

    return chunk0, chunk1


def read_first_two_ciphertext_chunks(filename):
    """
    Đọc hai chunk ciphertext đầu tiên từ book.enc.

    Bỏ qua 16-byte prefix.
    """

    with open(filename, "rb") as file:

        # Bỏ prefix
        prefix = file.read(PREFIX_SIZE)

        if len(prefix) != PREFIX_SIZE:
            raise ValueError("Không đọc đủ prefix.")

        chunk0 = file.read(CHUNK_SIZE)
        chunk1 = file.read(CHUNK_SIZE)

    return chunk0, chunk1


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("TASK 4 - ENCRYPTING A BOOK")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. Tạo key 32 bytes
    # --------------------------------------------------------

    key = random(KEY_SIZE)

    print("\n[1] KEY")
    print("Key:", key.hex())
    print("Key length:", len(key), "bytes")

    # --------------------------------------------------------
    # 2. Kiểm tra book.pdf
    # --------------------------------------------------------

    print("\n[2] INPUT FILE")

    try:
        with open(INPUT_FILE, "rb") as file:
            file.seek(0, 2)
            book_size = file.tell()

    except FileNotFoundError:
        print(f"Không tìm thấy {INPUT_FILE}.")
        print("Hãy chạy:")
        print("curl -O https://toc.cryptobook.us/book.pdf")
        return

    print("book.pdf size:", book_size, "bytes")
    print("book.pdf size:", book_size / (1024 * 1024), "MiB")

    # --------------------------------------------------------
    # 3. Encrypt book.pdf
    # --------------------------------------------------------

    print("\n[3] ENCRYPTING...")

    (
        prefix,
        plaintext_size,
        ciphertext_size,
        number_of_chunks,
        encryption_time
    ) = encrypt_book(
        INPUT_FILE,
        ENCRYPTED_FILE,
        key
    )

    print("Encryption completed.")

    print("Number of chunks:", number_of_chunks)
    print("Plaintext bytes:", plaintext_size)
    print("Ciphertext bytes:", ciphertext_size)
    print("Prefix bytes:", len(prefix))
    print(f"Encryption time: {encryption_time:.4f} seconds")

    # --------------------------------------------------------
    # 4. Kích thước book.enc
    # --------------------------------------------------------

    encrypted_file_size = None

    with open(ENCRYPTED_FILE, "rb") as file:
        file.seek(0, 2)
        encrypted_file_size = file.tell()

    print("\n[4] FILE SIZES")

    print("book.pdf :", book_size, "bytes")
    print("book.enc :", encrypted_file_size, "bytes")

    print(
        "Difference:",
        encrypted_file_size - book_size,
        "bytes"
    )

    # --------------------------------------------------------
    # 5. First 16 bytes plaintext
    # --------------------------------------------------------

    print("\n[5] FIRST 16 BYTES")

    first_plaintext = read_first_bytes(
        INPUT_FILE,
        16
    )

    print(
        "Plaintext first 16 bytes :",
        first_plaintext.hex()
    )

    # --------------------------------------------------------
    # 6. First 16 bytes ciphertext
    # --------------------------------------------------------

    first_ciphertext = read_first_ciphertext_bytes(
        ENCRYPTED_FILE,
        16
    )

    print(
        "Ciphertext first 16 bytes:",
        first_ciphertext.hex()
    )

    # --------------------------------------------------------
    # 7. Decrypt
    # --------------------------------------------------------

    print("\n[6] DECRYPTING...")

    (
        decrypt_prefix,
        decrypted_ciphertext_size,
        decrypted_plaintext_size,
        decrypt_chunks
    ) = decrypt_book(
        ENCRYPTED_FILE,
        DECRYPTED_FILE,
        key
    )

    print("Decryption completed.")

    print(
        "Decrypted plaintext size:",
        decrypted_plaintext_size,
        "bytes"
    )

    print(
        "Number of chunks:",
        decrypt_chunks
    )

    # --------------------------------------------------------
    # 8. SHA-256
    # --------------------------------------------------------

    print("\n[7] SHA-256")

    original_hash = sha256_file(INPUT_FILE)
    decrypted_hash = sha256_file(DECRYPTED_FILE)

    print("SHA-256 book.pdf     :", original_hash)
    print("SHA-256 book.dec.pdf :", decrypted_hash)

    if original_hash == decrypted_hash:
        print("SHA-256 MATCH: True")
    else:
        print("SHA-256 MATCH: False")

    # --------------------------------------------------------
    # 9. Kiểm tra prefix
    # --------------------------------------------------------

    print("\n[8] PREFIX CHECK")

    print("Original prefix :", prefix.hex())
    print("Decrypt prefix  :", decrypt_prefix.hex())

    print(
        "Prefix matches:",
        prefix == decrypt_prefix
    )

    # --------------------------------------------------------
    # 10. BUGGY ENCRYPTION
    # --------------------------------------------------------

    print("\n[9] BUGGY ENCRYPTION")
    print("Forgetting the counter...")
    print("Every chunk uses: prefix || 0")

    (
        buggy_plaintext_size,
        buggy_ciphertext_size,
        buggy_chunks
    ) = encrypt_book_buggy(
        INPUT_FILE,
        BUGGY_ENCRYPTED_FILE,
        key,
        prefix
    )

    print("Buggy encryption completed.")
    print("Number of chunks:", buggy_chunks)

    # --------------------------------------------------------
    # 11. Đọc m0, m1
    # --------------------------------------------------------

    print("\n[10] FIRST TWO PLAINTEXT CHUNKS")

    m0, m1 = read_first_two_chunks(INPUT_FILE)

    print("m0 size:", len(m0), "bytes")
    print("m1 size:", len(m1), "bytes")

    # --------------------------------------------------------
    # 12. Đọc c0, c1 của bản đúng
    # --------------------------------------------------------

    print("\n[11] FIRST TWO CORRECT CIPHERTEXT CHUNKS")

    c0, c1 = read_first_two_ciphertext_chunks(
        ENCRYPTED_FILE
    )

    print("c0 size:", len(c0), "bytes")
    print("c1 size:", len(c1), "bytes")

    # Nếu chunk cuối/đặc biệt không cùng độ dài,
    # chỉ XOR phần có cùng độ dài.
    correct_compare_size = min(
        len(c0),
        len(c1),
        len(m0),
        len(m1)
    )

    correct_result = (
        xor_bytes(
            c0[:correct_compare_size],
            c1[:correct_compare_size]
        )
        ==
        xor_bytes(
            m0[:correct_compare_size],
            m1[:correct_compare_size]
        )
    )

    print(
        "Correct encryption:",
        "c0 XOR c1 == m0 XOR m1 ->",
        correct_result
    )

    # --------------------------------------------------------
    # 13. Đọc c0, c1 của bản BUGGY
    # --------------------------------------------------------

    print("\n[12] FIRST TWO BUGGY CIPHERTEXT CHUNKS")

    buggy_c0, buggy_c1 = read_first_two_ciphertext_chunks(
        BUGGY_ENCRYPTED_FILE
    )

    print("buggy c0 size:", len(buggy_c0), "bytes")
    print("buggy c1 size:", len(buggy_c1), "bytes")

    buggy_compare_size = min(
        len(buggy_c0),
        len(buggy_c1),
        len(m0),
        len(m1)
    )

    buggy_result = (
        xor_bytes(
            buggy_c0[:buggy_compare_size],
            buggy_c1[:buggy_compare_size]
        )
        ==
        xor_bytes(
            m0[:buggy_compare_size],
            m1[:buggy_compare_size]
        )
    )

    print(
        "Buggy encryption:",
        "c0 XOR c1 == m0 XOR m1 ->",
        buggy_result
    )

    # --------------------------------------------------------
    # 14. Kết luận
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("TASK 4 COMPLETED")
    print("=" * 70)

    print("\nFiles created:")
    print("-", ENCRYPTED_FILE)
    print("-", DECRYPTED_FILE)
    print("-", BUGGY_ENCRYPTED_FILE)

    print("\nExpected important results:")
    print("- book.enc is book.pdf + 16 bytes")
    print("- SHA-256(book.pdf) == SHA-256(book.dec.pdf)")
    print("- Correct encryption should NOT reuse the same keystream")
    print("- Buggy encryption should give:")
    print("  c0 XOR c1 == m0 XOR m1 -> True")

    print("\nDone.")


if __name__ == "__main__":
    main()