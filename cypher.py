from itertools import cycle

def vigenere_decrypt(ciphertext, key):
    """Decrypt the Vigenère cipher with a given key."""
    decrypted = ""
    key_cycle = cycle(key)  # Create a cycle iterator for the key

    for char in ciphertext:
        if char.isalpha():  # Check if the character is a letter
            # Convert letters to numbers 0-25, perform the shift, and convert back to a letter
            shifted = (ord(char) - ord('a') - (ord(next(key_cycle)) - ord('a'))) % 26 + ord('a')
            decrypted += chr(shifted)
        else:
            # If the character isn't a letter, leave it as it is
            decrypted += char

    return decrypted

def main():
    input_path = r"C:\Users\Alex\Desktop\1.txt"
    output_path = r"C:\Users\Alex\Desktop\2.txt"
    ciphertext = "yexiwpnbjfzhcnpmswkorthnngaefltepxnkknpmswgeeywomnqucawnzqooxnxwswmhjywjlnombkywjlnxsrwkwomwjlnpmswrboynsnraxcnjo_etkw_wttwmhjywjlnexnbtkdzapnacewjisainpmopewoejdfgwyvaejkwrwmhjywjlnqxhxqzue_afaoewjepnngxnawkbtmhjywjlnstegxnhnyaegdnfwfncwbqunkknljblqswtawmbnxsoernjfojrwnawjwcmgajapmnzjapzeueeeiwjlnzqbpmsoeeeiswfekza_ejeyvwfnlfqgebberklfwavasnpmswibcxnlnqgehlegdjnohsjynkknxetkbnot_agb_cnyqbsxnxevkwawfa_egdjawibcxndteojfwfa_eeeisnxnxqzwhvxxswyvaetkbnkkgasnpmswkbteuayfwfjxcnyzgwntwsbpegdjn_tuoeuaynptneynyjtkwswyvaevqsgawfwfa_egafewngwybwuwahsoeooelkzninudynczsoxnesnxeqkzapwlwttwfaerohezk_snxnsmsnjnitfpecatchjndfiaezeyghjnabcawwasqaebbegdjndfeomsneeafzeywaxnkknjfgqwswkbtmhjywjlnexnoyeksuhcnkuckxs_epuefkrswuskuzaegdjnhjoczswfuxnaoynzwhaqnoubnyfwaojyfwngwro_jneqzaloheojinpmswhoiuoelawmooepajawxgafreqlwnapjaontunac"  # Replace with your ciphertext

    # Read all keys from the input file
    with open(input_path, 'r') as file:
        keys = file.readlines()

    # Prepare to write the decrypted texts to the output file
    with open(output_path, 'w') as file:
        for key in keys:
            key = key.strip()  # Remove any extra whitespace or newline characters
            decrypted_text = vigenere_decrypt(ciphertext.lower(), key.lower())
            file.write(f"Key: {key} -> {decrypted_text}\n")

if __name__ == "__main__":
    main()
