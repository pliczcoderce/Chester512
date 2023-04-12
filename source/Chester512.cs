using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Chester512
{
    public class Chester512
    {
        /// <summary>
        /// Chester512 is an encryption algorithm developed by Chester#1756 with the aim of providing a highly secure alternative to AES-256, specifically designed to challenge quantum computing attacks. This innovative algorithm utilizes a dynamically generated S-Box based on the user's password, along with multiple levels of expanded keys, in order to increase the non-linearity and complexity of the cipher.
        /// By incorporating these unique features, Chester512 seeks to minimize discernible patterns and enhance resistance to cryptanalysis, ultimately offering a more robust and resilient encryption solution.
        ///
        /// Chester512 introduces several key innovations compared to AES-256:
        ///
        /// | Feature            | Chester512                       | AES-256                          |
        /// |--------------------|----------------------------------|----------------------------------|
        /// | S-Box Generation   | Dynamic and password-dependent   | Static and predefined            |
        /// | Key Expansion      | Multi-level expanded keys        | Single level expanded keys       |
        /// | Non-linearity      | Enhanced through dynamic S-Box   | Rely on static S-Box             |
        /// | Quantum Resistance | Designed to challenge attacks    | Not specifically designed for it |
        ///
        /// These enhancements aim to provide an encryption algorithm that is more resilient to known and potential future attacks, especially those leveraging quantum computing capabilities.
        /// </summary>


        private readonly byte[] _key;
        private readonly byte[][] _expandedKey;
        private readonly byte[] _dynamicSBox;
        private const int NumberOfRounds = 20;
        private static readonly byte[] IrreduciblePolynomials = { 0x1B, 0x1D, 0x1F, 0x25, 0x29, 0x2B, 0x2D, 0x2F, 0x35, 0x39, 0x3B, 0x3D, 0x3F };
        private readonly byte _irreduciblePoly;

        /// <summary>
        /// Initializes a new instance of the Chester512 class with the specified key.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        public Chester512(byte[] key)
        {
            if (key.Length != 64)
            {
                throw new ArgumentException("Key must have 64 characters");
            }

            _key = key;
            _dynamicSBox = GenerateDynamicSBox(_key);
            _expandedKey = KeyExpansion(_key);
            _irreduciblePoly = DeriveIrreduciblePoly(_dynamicSBox);

            if (System.Diagnostics.Debugger.IsAttached)
            {
                PrintDynamicSBox();
                PrintExpandedKeys();
            }
        }

        /// <summary>
        /// Initializes a new instance of the Chester512 class with the specified key.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        public Chester512(SecureString secureKey)
        {
            var key = SecureStringToByteArray(secureKey);
            if (key.Length != 64)
            {
                throw new ArgumentException("Key must have 64 characters");
            }

            _key = key;
            _dynamicSBox = GenerateDynamicSBox(_key);
            _expandedKey = KeyExpansion(_key);
            _irreduciblePoly = DeriveIrreduciblePoly(_dynamicSBox);

            if (System.Diagnostics.Debugger.IsAttached)
            {
                PrintDynamicSBox();
                PrintExpandedKeys();
            }
        }

        /// <summary>
        /// Prints the dynamic S-Box.
        /// </summary>
        public void PrintDynamicSBox()
        {
            Console.WriteLine("Dynamic S-Box:");
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    Console.Write($"{_dynamicSBox[i * 16 + j]:X2} ");
                }
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Prints the expanded keys.
        /// </summary>
        public void PrintExpandedKeys()
        {
            for (int i = 0; i < _expandedKey.Length; i++)
            {
                Console.WriteLine($"Expanded Key Round {i}:");
                for (int j = 0; j < _expandedKey[i].Length; j += 4)
                {
                    Console.WriteLine($"{(char)_expandedKey[i][j]} {(char)_expandedKey[i][j + 1]} {(char)_expandedKey[i][j + 2]} {(char)_expandedKey[i][j + 3]}");
                }
                Console.WriteLine();
            }
        }

        /// <summary>
        /// Encrypts the specified plaintext using the Chester512 algorithm.
        /// </summary>
        /// <param name="plainText">The plaintext to encrypt.</param>
        /// <returns>The encrypted ciphertext.</returns>
        public byte[] Encrypt(byte[] plainText)
        {
            int blockSize = 64;
            int paddedLength = (plainText.Length + blockSize - 1) / blockSize * blockSize;
            byte[] paddedPlainText = new byte[paddedLength];
            Array.Copy(plainText, paddedPlainText, plainText.Length);

            byte[] encrypted = new byte[paddedLength];

            for (int i = 0; i < paddedLength; i += blockSize)
            {
                byte[] state = new byte[blockSize];
                Array.Copy(paddedPlainText, i, state, 0, blockSize);

                state = AddRoundKey(state, _expandedKey[0]);

                for (int round = 1; round <= NumberOfRounds; round++)
                {
                    var expandedKey = _expandedKey[round];

                    state = SubBytes(state);
                    state = ShiftRows(state, expandedKey, round);
                    state = MixColumns(state, _dynamicSBox);
                    state = AddRoundKey(state, expandedKey);
                }

                Array.Copy(state, 0, encrypted, i, blockSize);
            }

            return encrypted;
        }

        /// <summary>
        /// Decrypts the specified ciphertext using the Chester512 algorithm.
        /// </summary>
        /// <param name="cipherText">The ciphertext to decrypt.</param>
        /// <returns>The decrypted plaintext.</returns>
        public byte[] Decrypt(byte[] cipherText)
        {
            int blockSize = 64;

            byte[] decrypted = new byte[cipherText.Length];

            byte[] invDynamicSBox = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                invDynamicSBox[_dynamicSBox[i]] = (byte)i;
            }

            for (int i = 0; i < cipherText.Length; i += blockSize)
            {
                byte[] state = new byte[blockSize];
                Array.Copy(cipherText, i, state, 0, blockSize);

                for (int round = NumberOfRounds; round >= 1; round--)
                {
                    var expandedKey = _expandedKey[round];

                    state = AddRoundKey(state, expandedKey);
                    state = InvMixColumns(state, invDynamicSBox);
                    state = InvShiftRows(state, expandedKey, round);
                    state = InvSubBytes(state);
                }

                state = AddRoundKey(state, _expandedKey[0]);

                Array.Copy(state, 0, decrypted, i, blockSize);
            }

            return decrypted;
        }

        /// <summary>
        /// Converts a SecureString to a byte array.
        /// </summary>
        /// <returns>The byte array.</returns>
        private static byte[] SecureStringToByteArray(SecureString securePassword)
        {
            var unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                var passwordLength = securePassword.Length;

                var passwordBytesList = new List<byte>();

                for (int i = 0; i < passwordLength; i++)
                {
                    char currentChar = Marshal.PtrToStringUni(unmanagedString + i * 2, 1)[0];
                    byte[] currentCharBytes = Encoding.UTF8.GetBytes(new char[] { currentChar });

                    passwordBytesList.AddRange(currentCharBytes);
                }

                return passwordBytesList.ToArray();
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }


        /// <summary>
        /// Generates a secure password.
        /// </summary>
        /// <returns>The password byte array.</returns>
        public static byte[] GeneratePassword()
        {
            const int length = 64;

            byte[] randomBytes = new byte[length];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return randomBytes;
        }

        /// <summary>
        /// Derives an irreducible polynomial from the S-Box.
        /// </summary>
        /// <param name="sBox">The S-Box used in the cipher.</param>
        /// <returns>The derived irreducible polynomial.</returns>
        private byte DeriveIrreduciblePoly(byte[] sBox)
        {
            int index = sBox[0] % IrreduciblePolynomials.Length;
            return IrreduciblePolynomials[index];
        }

        /// <summary>
        /// Generates a dynamic S-Box based on the provided key.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <returns>The generated dynamic S-Box.</returns>
        private byte[] GenerateDynamicSBox(byte[] key)
        {
            byte[] sBox = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                sBox[i] = (byte)i;
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + sBox[i] + key[i % key.Length]) & 0xFF;
                byte temp = sBox[i];
                sBox[i] = sBox[j];
                sBox[j] = temp;
            }

            return sBox;
        }

        /// <summary>
        /// Expands the key for the specified number of rounds.
        /// </summary>
        /// <param name="key">The encryption key.</param>
        /// <returns>The expanded key for each round.</returns>
        private byte[][] KeyExpansion(byte[] key)
        {
            int blockSize = 64;
            byte[][] expandedKey = new byte[NumberOfRounds + 1][];

            for (int i = 0; i <= NumberOfRounds; i++)
            {
                expandedKey[i] = new byte[blockSize];
                if (i == 0)
                {
                    Array.Copy(key, expandedKey[i], blockSize);
                }
                else
                {
                    Array.Copy(expandedKey[i - 1], expandedKey[i], blockSize);
                    for (int j = 0; j < blockSize; j++)
                    {
                        // Rotate the byte by j positions
                        byte rotated = RotateLeft(expandedKey[i][j], j);

                        // Apply the substitution using the dynamic S-Box
                        byte substituted = Substitute(rotated, _dynamicSBox);

                        // XOR the result with a round-dependent value
                        expandedKey[i][j] = (byte)(substituted ^ (i * (j + 1)));
                    }
                }
            }

            return expandedKey;
        }

        /// <summary>
        /// Rotates the bits in a byte to the left by the specified number of positions.
        /// </summary>
        /// <param name="value">The byte to rotate.</param>
        /// <param name="shift">The number of positions to rotate.</param>
        /// <returns>The rotated byte.</returns>
        private byte RotateLeft(byte value, int shift)
        {
            return (byte)((value << shift) | (value >> (8 - shift)));
        }

        /// <summary>
        /// Substitutes a byte using the provided S-Box.
        /// </summary>
        /// <param name="value">The byte to substitute.</param>
        /// <param name="sBox">The S-Box used for substitution.</param>
        /// <returns>The substituted byte.</returns>
        private byte Substitute(byte value, byte[] sBox)
        {
            return sBox[value];
        }

        /// <summary>
        /// Combines the state and round key using XOR.
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <param name="roundKey">The round key.</param>
        /// <returns>The resulting state after adding the round key.</returns>
        private byte[] AddRoundKey(byte[] state, byte[] roundKey)
        {
            return state.Zip(roundKey, (s, k) => (byte)(s ^ k)).ToArray();
        }

        /// <summary>
        /// Mixes the columns of the state using the provided S-Box.
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <param name="sbox">The S-Box used for mixing columns.</param>
        /// <returns>The resulting state after mixing columns.</returns>
        private byte[] MixColumns(byte[] state, byte[] sbox)
        {
            byte[] result = new byte[state.Length];

            for (int i = 0; i < state.Length; i += 4)
            {
                byte[] temp = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    temp[j] = sbox[state[i + j]];
                }

                result[i] = (byte)(GaloisFieldMultiply(temp[0], 0x02) ^ GaloisFieldMultiply(temp[1], 0x03) ^ temp[2] ^ temp[3]);
                result[i + 1] = (byte)(temp[0] ^ GaloisFieldMultiply(temp[1], 0x02) ^ GaloisFieldMultiply(temp[2], 0x03) ^ temp[3]);
                result[i + 2] = (byte)(temp[0] ^ temp[1] ^ GaloisFieldMultiply(temp[2], 0x02) ^ GaloisFieldMultiply(temp[3], 0x03));
                result[i + 3] = (byte)(GaloisFieldMultiply(temp[0], 0x03) ^ temp[1] ^ temp[2] ^ GaloisFieldMultiply(temp[3], 0x02));
            }

            return result;
        }

        /// <summary>
        /// Inverse mixes the columns of the state using the provided inverse S-Box.
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <param name="invSbox">The inverse S-Box used for inverse mixing columns.</param>
        /// <returns>The resulting state after inverse mixing columns.</returns>
        private byte[] InvMixColumns(byte[] state, byte[] invSbox)
        {
            byte[] result = new byte[state.Length];

            for (int i = 0; i < state.Length; i += 4)
            {
                byte[] temp = new byte[4];
                for (int j = 0; j < 4; j++)
                {
                    temp[j] = state[i + j];
                }

                byte[] mixed = new byte[4];
                mixed[0] = (byte)(GaloisFieldMultiply(temp[0], 0x0E) ^ GaloisFieldMultiply(temp[1], 0x0B) ^ GaloisFieldMultiply(temp[2], 0x0D) ^ GaloisFieldMultiply(temp[3], 0x09));
                mixed[1] = (byte)(GaloisFieldMultiply(temp[0], 0x09) ^ GaloisFieldMultiply(temp[1], 0x0E) ^ GaloisFieldMultiply(temp[2], 0x0B) ^ GaloisFieldMultiply(temp[3], 0x0D));
                mixed[2] = (byte)(GaloisFieldMultiply(temp[0], 0x0D) ^ GaloisFieldMultiply(temp[1], 0x09) ^ GaloisFieldMultiply(temp[2], 0x0E) ^ GaloisFieldMultiply(temp[3], 0x0B));
                mixed[3] = (byte)(GaloisFieldMultiply(temp[0], 0x0B) ^ GaloisFieldMultiply(temp[1], 0x0D) ^ GaloisFieldMultiply(temp[2], 0x09) ^ GaloisFieldMultiply(temp[3], 0x0E));

                for (int j = 0; j < 4; j++)
                {
                    result[i + j] = invSbox[mixed[j]];
                }
            }

            return result;
        }

        /// <summary>
        /// Multiplies two bytes in the Galois field.
        /// </summary>
        /// <param name="a">The first byte to multiply.</param>
        /// <param name="b">The second byte to multiply.</param>
        /// <returns>The result of the multiplication.</returns>
        private byte GaloisFieldMultiply(byte a, byte b)
        {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            byte irreduciblePoly = _irreduciblePoly;

            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                {
                    a ^= irreduciblePoly;
                }
                b >>= 1;
            }
            return p;
        }

        /// <summary>
        /// Applies the SubBytes transformation to the state.
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <returns>The resulting state after the SubBytes transformation.</returns>
        private byte[] SubBytes(byte[] state)
        {
            return state.Select(b => _dynamicSBox[b]).ToArray();
        }

        /// <summary>
        /// Applies the inverse SubBytes transformation to the state.
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <returns>The resulting state after the inverse SubBytes transformation.</returns>
        private byte[] InvSubBytes(byte[] state)
        {
            byte[] invDynamicSBox = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                invDynamicSBox[_dynamicSBox[i]] = (byte)i;
            }

            return state.Select(b => invDynamicSBox[b]).ToArray();
        }

        /// <summary>
        /// Shifts the rows of the state based on the expanded key and current round.
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <param name="expandedKey">The expanded key.</param>
        /// <param name="round">The current round number.</param>
        /// <returns>The resulting state after the ShiftRows transformation.</returns>
        private byte[] ShiftRows(byte[] state, byte[] expandedKey, int round)
        {
            byte[] result = new byte[state.Length];
            int shift = expandedKey[((round * 16) - 1) % expandedKey.Length] % 4;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[j * 16 + i] = state[j * 16 + ((i + j * shift) % 16)];
                }
            }
            return result;
        }

        /// <summary>
        /// Applies the inverse ShiftRows transformation to the state based on the expanded key and current round.
        /// </summary>
        /// <param name="state">The current state of the cipher.</param>
        /// <param name="expandedKey">The expanded key.</param>
        /// <param name="round">The current round number.</param>
        /// <returns>The resulting state after the inverse ShiftRows transformation.</returns>
        private byte[] InvShiftRows(byte[] state, byte[] expandedKey, int round)
        {
            byte[] result = new byte[state.Length];
            int shift = expandedKey[((round * 16) - 1) % expandedKey.Length] % 4;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[j * 16 + i] = state[j * 16 + ((i - j * shift + 16) % 16)];
                }
            }
            return result;
        }
    }
}