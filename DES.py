import Tables

# Fungsi untuk mengubah string menjadi binary
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

# Fungsi untuk mengubah binary menjadi string ASCII
def binary_to_ascii(bin_str):
    ascii_str = ''.join([chr(int(bin_str[i:i+8], 2)) for i in range(0, len(bin_str), 8)])
    return ascii_str

# Fungsi untuk melakukan initial permutation (IP) pada plaintext
def ip_on_bin_rep(bin_rep):
    # Inisialisasi ip_result untuk menyimpan hasil permutasi
    ip_result = [None] * 64
    
    # Lakukan permutasi sesuai dengan tabel IP
    for i in range(64):
        ip_result[i] = bin_rep[Tables.ip_table[i] - 1]

    # Gabungkan hasil permutasi menjadi satu string
    ip_result_str = ''.join(ip_result)
    
    return ip_result_str

# Fungsi untuk mengkonversi key menjadi bentuk binary-nya
def key_in_binary_conv(original_key):
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

# Fungsi untuk mengenerate key untuk setiap round
def generate_round_keys(original_key):
    # Ubah key menjadi binary
    binary_key_res = key_in_binary_conv(original_key)

    # Lakukan permutasi PC1
    pc1_key_str = ''.join(binary_key_res[bit - 1] for bit in Tables.pc1_table)
    
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

# Fungsi untuk melakukan enkripsi
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
    final_cipher_ascii = binary_to_ascii(final_cipher_str)
    
    return final_cipher_ascii

# Fungsi untuk Dekripsi cipher text menjadi original plain text
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
    cipher_text_ascii = binary_to_ascii(cipher_text_str)

    return cipher_text_ascii

# Fungsi untuk split text menjadi beberapa bagian dengan panjang yang ditentukan
def split_text(text, length):
    # Split text menjadi beberapa bagian dengan panjang length
    return [text[i:i+length] for i in range(0, len(text), length)]

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

if __name__ == "__main__":
    main()