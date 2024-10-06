# Tugas_Keamanan-Informasi_DES
Project ini menjelaskan tentang bagaimana implementasi dari DES(Data Encryption Standard) di dalam python

## Nama
Muhammad Zhafran(5025211100)

## Penjelasan Code

### Tables.py
Berisi tabel-tabel yang digunakan dalam implementasi DES. Tabel-tabel tersebut bernilai tetap mengikuti standar DES.
Berikut adalah tabel-tabel yang digunakan:
- ip_table
```
ip_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]
```
Tabel ip_table atau Initial Permutation Table digunakan pada permutasi awal sebelum plain_text dienkripsi
- pc1_table
```
pc1_table = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]
```
Tabel pc1_table atau Permutation Choice 1 Table digunakan untuk mengatur bit-bit yang akan digunakan sebagai subkey pada setiap ronde DES.

- pc2_table
```
pc2_table = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]
```
Tabel pc2_table atau Permutation Choice 2 Table digunakan untuk mengatur bit-bit yang akan digunakan sebagai subkey pada setiap ronde DES.

- shift_schedule
```
shift_schedule = [1, 1, 2, 2,
                  2, 2, 2, 2,
                  1, 2, 2, 2,
                  2, 2, 2, 1]
```
Tabel shift_schedule merupakan schedule pergeseran bit pada key scheduling, menentukan seberapa banyak bit yang akan digeser pada setiap ronde DES.

- e_box_table
```
e_box_table = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]
```
Tabel e_box_table atau Expansion box table digunakan untuk mengubah 32-bit menjadi 48-bit.

- s_boxes
```
s_boxes = [
    # S-box 1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S-box 2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S-box 3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S-box 4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S-box 5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S-box 6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S-box 7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S-box 8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]
```
Tabel s-box atau Substituition boxes (S-boxes), berjumlah 8, masing-masing berfungsi sebagai peta dalam substitusi yang mengambil 6-bit dan menghasilkan output 8-bit.

- p_box_table
```
p_box_table = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]
```
Tabel p-box_table atau permutation boxes table digunakan setelah substitusi S-Box untuk permutasi pada bit-bit yang dihasilkan

- ip_inverse_table
```
ip_inverse_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]
```
Tabel ip_inverse_table atau Initial Permutation Invers Table digunakan untuk melakukan dekripsi.


### DES.py
- function split_text(text, length)
```
def split_text(text, length):
    # Split text menjadi beberapa bagian dengan panjang length
    return [text[i:i+length] for i in range(0, len(text), length)]
```
Fungsi untuk memisahkan text menjadi beberapa bagian dengan panjang yang diinginkan.

- function str_to_bin(plain_text)
```
def str_to_bin(plain_text):
        # Inisialisasi binary_res untuk menyimpan hasil
        bin_res = ''
        
        for char in plain_text:
            # Ubah nilai ASCII dari character ke binary
            bin_char = format(ord(char), '08b')
            bin_res += bin_char
            bin_res = bin_res[:64]
        
        # Tambah 0 dalam binary jika kurang agar menjadi 64 bits
        bin_res = bin_res[:64].ljust(64, '0')
        
        return bin_res
```
Fungsi untuk mengubah dari string menjadi bentuk binary nya.

- function bin_to_ascii(bin_str)
Fungsi untuk mengubah dari binary menjadi bentuk asciinya.
```
def bin_to_ascii(bin_str):
    ascii_str = ''.join([chr(int(bin_str[i:i+8], 2)) for i in range(0, len(bin_str), 8)])
    return ascii_str
```

- function ip_on_bin_rep(bin_rep)
```
def ip_on_bin_rep(bin_rep):
    # Inisialisasi ip_result untuk menyimpan hasil permutasi
    ip_result = [None] * 64
    
    # Lakukan permutasi sesuai dengan tabel IP
    for i in range(64):
        ip_result[i] = bin_rep[Tables.ip_table[i] - 1]

    # Gabungkan hasil permutasi menjadi satu string
    ip_result_str = ''.join(ip_result)
    
    return ip_result_str
```
Fungsi untuk melakukan initial permutation pada plain text

- function key_in_bin_conv(original_key)
Fungsi untuk mengubah key menjadi bentuk binary nya.
```
def key_in_bin_conv(original_key):
    # Inisialisasi binary_key_res untuk menyimpan hasil
    binary_key_res = ''
    
    for char in original_key:
    # Ubah character ke binary dan gabung agar terbentuk 64-bit binary string
        binary_key = format(ord(char), '08b') 
        binary_key_res += binary_key

    # Jika kurang dari 64 tambah 0
    if len(binary_key_res) < 64:
        binary_key_res = binary_key_res.ljust(64, '0')
    
    return binary_key_res
```
Fungsi untuk mengubah key menjadi bentuk binary nya.

- function generate_round_keys(original_key)
Fungsi untuk mengenerate round key untuk setaip round pada DES(16 round).
```
def generate_round_keys(original_key):
    # Ubah key menjadi binary
    bin_key_res = key_in_bin_conv(original_key)

    # Lakukan permutasi PC1
    pc1_key_str = ''.join(bin_key_res[bit - 1] for bit in Tables.pc1_table)
    
    # Split 56-bit key menjadi 2 buah 28-bit
    c0 = pc1_key_str[:28]
    d0 = pc1_key_str[28:]
    round_keys = []
    for round_num in range(16):
        # Lakukan left circular shift pada C dan D
        c0 = c0[Tables.shift_schedule[round_num]:] + c0[:Tables.shift_schedule[round_num]]
        d0 = d0[Tables.shift_schedule[round_num]:] + d0[:Tables.shift_schedule[round_num]]

        # Gabung C dan D
        cd_concatenated = c0 + d0

        # Lakukan permutasi PC2
        round_key = ''.join(cd_concatenated[bit - 1] for bit in Tables.pc2_table)

        # Simpan kunci di round ini ke dalam list untuk enkripsi dan dekripsi nanti
        round_keys.append(round_key)
    return round_keys
```
Fungsi untuk mengenerate round key untuk setaip round pada DES(16 round).

- function encryption(plain_text, key)
Fungsi untuk mengenkripsi plain text menjadi cipher text dengan bantuan key dan fungsi-fungsi sebelumnya.
```
def encryption(plain_text, key):
    # Ubah plain text ke binary
    plain_bin = str_to_bin(plain_text)

    # Generate round key
    round_keys = generate_round_keys(key)

    # Lakukan Initial Permutation (IP) pada plaintext untuk memproduksi 64-bit block
    ip_result_str = ip_on_bin_rep(plain_bin)

    # Bagi 64-bit block menjadi 2 buah 32-bit block, lpt (left plaintext) dan rpt (right plaintext)
    lpt = ip_result_str[:32]
    rpt = ip_result_str[32:]

    # Lakukan 16 round enkripsi DES
    for round_num in range(16):
        # Lakukan ekspansi dari 32 bits menjadi 48 bits
        expanded_result = [rpt[i - 1] for i in Tables.e_box_table]

        # Ubah hasilnya menjadi string
        expanded_result_str = ''.join(expanded_result)

        # Inisialisasi round_key_str sebagai round_key pada round ini
        round_key_str = round_keys[round_num]

        # Lakukan XOR(^) antara expanded_result_str dengan round_key_str
        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))

        # Split 48-bit hasil XOR menjadi 8 buah 6-bit group
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]

        # Inisialisasi s_box_substituted
        s_box_substituted = ''

        # Lakukan S-box substitution untuk setiap 6-bit group
        for i in range(8):
            # Bit pertama dan terakhir menentukan baris, sedangkan 4 bit tengah menentukan kolom
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            col_bits = int(six_bit_groups[i][1:-1], 2)

            # Ambil nilai yang sesuai dari S-box
            s_box_value = Tables.s_boxes[i][row_bits][col_bits]
            
            # Ubah hasilnya menjadi 4-bit binary string dan tambahkan ke s_box_substituted
            s_box_substituted += format(s_box_value, '04b')

        # Lakukan permutasi P-box pada hasil S-box substitution
        p_box_result = [s_box_substituted[i - 1] for i in Tables.p_box_table]

        # Ubah LPT menjadi list untuk operasi XOR
        lpt_list = list(lpt)

        # Lakukan XOR(^) antara LPT dengan hasil P-box substitution
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

        # Ubah hasilnya menjadi string
        new_rpt_str = ''.join(new_rpt)

        # Update LPT dan RPT untuk round selanjutnya
        lpt = rpt
        rpt = new_rpt_str

    # Reverse lpt dan rpt
    final_result = rpt + lpt

    # Lakukan 64-bit permutasi terakhir (IP-1) pada hasil enkripsi untuk mendapatkan ciphertext akhir
    final_cipher = [final_result[Tables.ip_inverse_table[i] - 1] for i in range(64)]

    # Ubah hasil akhir menjadi string
    final_cipher_str = ''.join(final_cipher)

    # Ubah binary cipher ke ascii
    final_cipher_ascii = bin_to_ascii(final_cipher_str)
    
    return final_cipher_ascii
```
Fungsi untuk mengenkripsi plain text menjadi cipher text dengan bantuan key dan fungsi-fungsi sebelumnya.

- function decryption(cipher_text, key)
```
def decryption(cipher_text, key):
    # Ubah cipher text ke binary
    cipher_text = str_to_bin(cipher_text)

    # Inisialisasi round_keys untuk dekripsi
    round_keys = generate_round_keys(key)
    
    # lakukan 64-bit permutasi terakhir (IP-1) pada cipher text untuk mendapatkan 64-bit block
    ip_dec_result_str = ip_on_bin_rep(cipher_text)
    
    # split 64-bit block menjadi 2 buah 32-bit block, lpt (left plaintext) dan rpt (right plaintext)
    lpt = ip_dec_result_str[:32]
    rpt = ip_dec_result_str[32:]

    for round_num in range(16):
        # Lakukan ekspansi dari 32 bits menjadi 48 bits
        expanded_result = [rpt[i - 1] for i in Tables.e_box_table]
    
        # Ubah 48-bit hasil ekspansi menjadi string
        expanded_result_str = ''.join(expanded_result)

        # Inisialisasi 48-bit round_key_str sebagai round_key pada round ini
        round_key_str = round_keys[15-round_num]
    
        # Lakukan XOR(^) antara expanded_result_str dengan round_key_str
        xor_result_str = ''
        for i in range(48):
            xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))
    
        # Split 48-bit hasil XOR menjadi 8 buah 6-bit group
        six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]
    
        # Inisialisasi s_box_substituted
        s_box_substituted = ''
    
        # Lakukan S-box substitution untuk setiap 6-bit group
        for i in range(8):
            # Bit pertama dan terakhir menentukan baris, sedangkan 4 bit tengah menentukan kolom
            row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
            col_bits = int(six_bit_groups[i][1:-1], 2)
    
            # Ambil nilai yang sesuai dari S-box
            s_box_value = Tables.s_boxes[i][row_bits][col_bits]
            
            # Ubah hasilnya menjadi 4-bit binary string dan tambahkan ke s_box_substituted
            s_box_substituted += format(s_box_value, '04b')
    
        # Lakukan permutasi P-box pada hasil S-box substitution
        p_box_result = [s_box_substituted[i - 1] for i in Tables.p_box_table]
    
        # Ubah LPT menjadi list untuk operasi XOR
        lpt_list = list(lpt)
    
        # Lakukan XOR(^) antara LPT dengan hasil P-box substitution
        new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]
    
        # Ubah hasilnya menjadi string
        new_rpt_str = ''.join(new_rpt)
    
        # Update LPT dan RPT untuk round selanjutnya
        lpt = rpt
        rpt = new_rpt_str
    
    # Reverse lpt dan rpt
    final_result = rpt + lpt

    # Lakukan 64-bit permutasi terakhir (IP-1) pada hasil dekripsi untuk mendapatkan plaintext akhir
    cipher_text = [final_result[Tables.ip_inverse_table[i] - 1] for i in range(64)]

    # Ubah hasil akhir menjadi string
    cipher_text_str = ''.join(cipher_text)

    # Ubah binary cipher ke ascii
    cipher_text_ascii = bin_to_ascii(cipher_text_str)

    return cipher_text_ascii
```
Fungsi untuk mendeskripsi cipher text menjadi plain text dengan bantuan key dan fungsi-fungsi sebelumnya.

- function main()
```
def main():
    # Input plain text untuk dienkripsi dan key nya
    plain_text = input("Masukan Plain Text: ")
    key = input("Masukan Key: ")

    # Bagi menjadi beberapa bagian yang masing-masing berjumlah 8 character
    plain_per8 = split_text(plain_text, 8)
    key_per8 = split_text(key, 8)

    # Memastikan bahwa panjang key sama dengan input dengan menulis ulang key sampai panjangnya sama atau lebih, lalu akan ditruncate agar panjangnya sama
    if len(key_per8) < len(plain_per8):
        key_per8 *= len(plain_per8) // len(key_per8) + 1
    key_per8 = key_per8[:len(plain_per8)]

    # Enkripsi setiap bagian
    print("\nBagian Enkripsi")
    encrypted_chunks = [encryption(chunk, key) for chunk, key in zip(plain_per8, key_per8)]
    encrypted_text = ''.join(encrypted_chunks)
    print(f"Encrypted text: {encrypted_text}")

    # Dekripsi setiap bagian
    print("\nBagian Dekripsi")
    decrypted_chunks = [decryption(chunk, key) for chunk, key in zip(encrypted_chunks, key_per8)]
    decrypted_text = ''.join(decrypted_chunks)
    print(f"Decrypted text: {decrypted_text}")
```
Fungsi utama untuk menjalankan semua code.
