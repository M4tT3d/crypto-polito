from Crypto.Util.strxor import strxor
import numpy
import string

CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
    'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
    'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
    'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182
}

# il problema è che viene riutilizzato lo stesso keystream per cifrare più righe
# questo ci permette di indovinare il keystream e di decifrare il testo
# Dopo aver trovato un keystream abbastanza buono da poter decifrare qualche
# parola, ho cercato il nome del file e ho trovato la sua versione non cifrata 
# in quanto è un documento pubblico
# Successivamente ho notato che alcuni pezzi di testo che erano stati cifrati,
# venivano da questo testo pubblico. Quindi ho sistemato il keystream 
# col plaintext trovato nel documento. Alla fine il testo che mi ha permesso 
# di decifrare il resto del testo è stata una riga in particolare che aveva una 
# parola diversa della versione pubblica. CTF andava a sostituire la parola 
# world 


with open("files/hacker-manifesto.enc", "r") as f:
    ciphertext_lines = [bytes.fromhex(x.strip()) for x in f.readlines()]
    print("Stats:")
    print("Number of lines:", len(ciphertext_lines))
    max_len = max([len(x) for x in ciphertext_lines])
    min_len = min([len(x) for x in ciphertext_lines])
    print("Length of the longest line:", max_len)
    print("Length of the shortest line:", min_len)
    def fix_keystream(str, pos, keystream, ciph):
        for i in range(len(str)):
            dec = keystream[i+pos] ^ ciph[i+pos]
            mask = dec ^ ord(str[i])
            keystream[i+pos] = keystream[i+pos] ^ mask
        return keystream
    #cerco di indovinare ogni byte della riga
    candidates_list = []
    for byte_to_guess in range(max_len):
        freqs = numpy.zeros(256, dtype=float)

        for guessed_byte in range(256):
            for c in ciphertext_lines:
                if byte_to_guess >= len(c):
                    continue
                char = chr(c[byte_to_guess] ^ guessed_byte)
                if char in string.printable:
                    freqs[guessed_byte] += CHARACTER_FREQ.get(char.lower(),0)
        match_list = [(freqs[i], i) for i in range(256)]
        #ordino per avere i più frequenti all'inizio
        ordered_match_list = sorted(match_list, reverse=True)
        candidates_list.append(ordered_match_list)
    keystream = bytearray()
    for x in candidates_list:
        keystream += x[0][1].to_bytes(1, byteorder='big')
    dec = keystream[28] ^ ciphertext_lines[0][28]
    mask = dec ^ ord("o")
    keystream[28] = keystream[28] ^ mask
    dec = keystream[34] ^ ciphertext_lines[0][34]
    mask = dec ^ ord("f")
    keystream[34] = keystream[34] ^ mask
    keystream = fix_keystream("This is our CTF now... the world of the electron and the switch, the\n", 0, keystream, ciphertext_lines[0])
    print(keystream.hex())
    for c in ciphertext_lines:
        l = min(len(keystream), len(c))
        print("LEN Ciphertext:", len(c))
        print(strxor(c[:l], keystream[:l]))