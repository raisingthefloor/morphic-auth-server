// Copyright 2022 Raising the Floor - US, Inc.
//
// Licensed under the New BSD license. You may not use this file except in
// compliance with this License.
//
// You may obtain a copy of the License at
// https://github.com/raisingthefloor/morphic-auth-server/blob/master/LICENSE.txt
//
// The R&D leading to these results received funding from the:
// * Rehabilitation Services Administration, US Dept. of Education under
//   grant H421A150006 (APCP)
// * National Institute on Disability, Independent Living, and
//   Rehabilitation Research (NIDILRR)
// * Administration for Independent Living & Dept. of Education under grants
//   H133E080022 (RERC-IT) and H133E130028/90RE5003-01-00 (UIITA-RERC)
// * European Union's Seventh Framework Programme (FP7/2007-2013) grant
//   agreement nos. 289016 (Cloud4all) and 610510 (Prosperity4All)
// * William and Flora Hewlett Foundation
// * Ontario Ministry of Research and Innovation
// * Canadian Foundation for Innovation
// * Adobe Foundation
// * Consumer Electronics Association Foundation

using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using MigrateUsers.Morphic.Server.Core;
using Morphic.Core;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Morphic.Server.Core;

public struct CryptoUtils
{
    public static string GenerateCryptoRandomUrlEncodeSafeString(int numberOfBits)
    {
        // NOTE: as we are shaving the top two bits off of every byte (to evenly preserve entropy), we divide the number of bits by 6; if it's not evenly divisible, we return a few extra bits of random data
        var lengthInBytes = (int)Math.Ceiling((double)numberOfBits / 6.0);
        var cryptoGeneratedBytes = RandomNumberGenerator.GetBytes(lengthInBytes);

        // NOTE: we map 64 bit values to uppercase and lowercase English alphabhet characters--plus digits 0 through 9, the period and the underscore; these are the "unreserved" urlencode-safe characters (in addition to '-' and '~'); 
        //       we avoid using '-' because we use it as our own semi-reserved prepend separator, such as in prepending region ids to oauth tokens and client ids
        string sixtyFourBitConversionMap = ".0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

        StringBuilder result = new();
        foreach (var cryptoGeneratedByte in cryptoGeneratedBytes)
        {
            var sixBits = cryptoGeneratedByte % 64;
            var urlEncodeSafeChar = sixtyFourBitConversionMap.Substring(sixBits, 1);
            result.Append(urlEncodeSafeChar);
        }

        return result.ToString();
    }

    public record CryptoError : MorphicAssociatedValueEnum<CryptoError.Values>
    {
        // enum members
        public enum Values
        {
            CryptoFailure,
        }

        // functions to create member instances
        public static CryptoError CryptoFailure(Exception exception) => new(Values.CryptoFailure) { Exception = exception };

        // associated values
        public Exception? Exception { get; private set; }

        // verbatim required constructor implementation for MorphicAssociatedValueEnums
        private CryptoError(Values value) : base(value) { }
    }

    // NOTE: if the IV is not provided, we generate an IV for each encryption operation and prepend it to the resulting cyphertext
    public static async Task<MorphicResult<string, CryptoError>> EncryptAndConvertToBase64StringAsync(string cleartext, byte[] aesKey, byte[]? iv) {
        var encryptAsyncResult = await CryptoUtils.EncryptAsync(cleartext, aesKey, iv);
        if (encryptAsyncResult.IsError == true)
        {
            return MorphicResult.ErrorResult(encryptAsyncResult.Error!);
        }
        var encryptedValueAsBytes = encryptAsyncResult.Value!;
        var result = Convert.ToBase64String(encryptedValueAsBytes);

        return MorphicResult.OkResult(result);
    }

    public static async Task<MorphicResult<byte[], CryptoError>> EncryptAsync(string cleartext, Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction)
    {
        var (aesKey, aesIV) = cryptoSecretsFunction();

        var result = await CryptoUtils.EncryptAsync(cleartext, aesKey, aesIV);
        return result;
    }

    public static async Task<byte[]> EncryptAsync_Throws(string cleartext, Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction)
    {
        var encryptResult = await CryptoUtils.EncryptAsync(cleartext, cryptoSecretsFunction);
        if (encryptResult.IsError == true)
        {
            switch (encryptResult.Error!.Value)
            {
                case CryptoUtils.CryptoError.Values.CryptoFailure:
                    var ex = encryptResult.Error!.Exception!;
                    throw ex;
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var encryptedValue = encryptResult.Value!;

        return encryptedValue;
    }

    public static async Task<MorphicResult<byte[], CryptoError>> EncryptAsync(string cleartext, byte[] aesKey, byte[]? iv)
    {
        var aes = Aes.Create();

        aes.Key = aesKey;
        if (iv is not null)
        {
            aes.IV = iv!;
        }

        byte[] memoryContents;
        using (MemoryStream memoryStream = new())
        {
            if (iv is null)
            {
                memoryStream.Write(aes.IV);
            }

            try
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (StreamWriter encryptWriter = new(cryptoStream))
                    {
                        await encryptWriter.WriteAsync(cleartext);
                    }
                }
            }
            catch (Exception ex)
            {
                return MorphicResult.ErrorResult(CryptoError.CryptoFailure(ex));
            }

            memoryContents = memoryStream.ToArray();
        }

        return MorphicResult.OkResult(memoryContents);
    }

    // NOTE: if the IV is not provided, we generate an IV for each encryption operation and prepend it to the resulting cyphertext
    public static async Task<MorphicResult<string, CryptoError>> EncryptAndConvertToUrlBase64StringAsync(string cleartext, byte[] aesKey, byte[]? iv) {
        var encryptAsBase64StringResult = await CryptoUtils.EncryptAndConvertToBase64StringAsync(cleartext, aesKey, iv);
        if (encryptAsBase64StringResult.IsError == true) 
        {
            return MorphicResult.ErrorResult(encryptAsBase64StringResult.Error!);
        }
        var base64String = encryptAsBase64StringResult.Value!;

        var urlBase64String = Base64Utils.ConvertBase64StringToUrlBase64String(base64String);
        return MorphicResult.OkResult(urlBase64String);
    }

    // NOTE: if the IV is not provided, we generate an IV for each encryption operation and prepend it to the resulting cyphertext
    public static async Task<MorphicResult<string, CryptoError>> ConvertFromBase64StringAndDecryptAsync(string encodedCiphertext, byte[] aesKey, byte[]? iv) {
        var aes = Aes.Create();

        aes.Key = aesKey;

        byte[] memoryContents = Convert.FromBase64String(encodedCiphertext);

        using (MemoryStream memoryStream = new(memoryContents))
        {
            if (iv is null)
            {
                byte[] ivBuffer = new byte[aes.IV.Length];
                memoryStream.Read(ivBuffer);
                aes.IV = ivBuffer;
            }
            else
            {
                aes.IV = iv!;
            }

            try 
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader decryptReader = new(cryptoStream))
                    {
                        var cleartext = await decryptReader.ReadToEndAsync();
                        return MorphicResult.OkResult(cleartext);
                    }
                }
            }
            catch (Exception ex)
            {
                return MorphicResult.ErrorResult(CryptoError.CryptoFailure(ex));
            }
        }
    }

    // NOTE: if the IV is not provided, we generate an IV for each encryption operation and prepend it to the resulting cyphertext
    public static async Task<MorphicResult<string, CryptoError>> ConvertFromUrlBase64StringAndDecryptAsync(string encodedCiphertext, byte[] aesKey, byte[]? iv) {
        var base64String = Base64Utils.ConvertUrlBase64StringToBase64String(encodedCiphertext);

        var decryptFromBase64StringResult = await CryptoUtils.ConvertFromBase64StringAndDecryptAsync(base64String, aesKey, iv);
        if (decryptFromBase64StringResult.IsError == true) 
        {
            return MorphicResult.ErrorResult(decryptFromBase64StringResult.Error!);
        }
        var cleartext = decryptFromBase64StringResult.Value!;

        return MorphicResult.OkResult(cleartext);
    }

    public static async Task<string> DecryptAsync_Throws(byte[] ciphertext, Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction)
    {
        var decryptResult = await CryptoUtils.DecryptAsync(ciphertext, cryptoSecretsFunction);
        if (decryptResult.IsError == true)
        {
            switch (decryptResult.Error!.Value)
            {
                case CryptoUtils.CryptoError.Values.CryptoFailure:
                    var ex = decryptResult.Error!.Exception!;
                    throw ex;
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var decryptedValue = decryptResult.Value!;

        return decryptedValue;
    }

    // NOTE: if the IV is not provided, we generate an IV for each encryption operation and prepend it to the resulting cyphertext
    public static async Task<MorphicResult<string, CryptoError>> DecryptAsync(byte[] ciphertext, Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction)
    {
        var (aesKey, aesIV) = cryptoSecretsFunction();

        var result = await CryptoUtils.DecryptAsync(ciphertext, aesKey, aesIV);
        return result;
    }

    // NOTE: if the IV is not provided, we generate an IV for each encryption operation and prepend it to the resulting cyphertext
    public static async Task<MorphicResult<string, CryptoError>> DecryptAsync(byte[] ciphertext, byte[] aesKey, byte[]? iv)
    {
        var aes = Aes.Create();

        aes.Key = aesKey;

        using (MemoryStream memoryStream = new(ciphertext))
        {
            if (iv is null)
            {
                byte[] ivBuffer = new byte[aes.IV.Length];
                memoryStream.Read(ivBuffer);
                aes.IV = ivBuffer;
            }
            else
            {
                aes.IV = iv!;
            }

            try
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (StreamReader decryptReader = new(cryptoStream))
                    {
                        var cleartext = await decryptReader.ReadToEndAsync();
                        return MorphicResult.OkResult(cleartext);
                    }
                }
            }
            catch (Exception ex)
            {
                return MorphicResult.ErrorResult(CryptoError.CryptoFailure(ex));
            }
        }
    }

    //

    private enum HashAlgorithmMarker: byte
    {
        PBkdf2WithHmacSha512_128bitSalt_512bitSubkey = 0x00,
    }

    public static byte[] SaltAndHashPassword(string password)
    {
        // settings for PBkdf2WithHmacSha512_128bitSalt_512bitSubkey
        var saltNumberOfBits = 128; // minimum recommended by NIST (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf page 6, captured 2022-02-18)
        var hashNumberOfBits = 512; 
        var hashKeyDerivationIterationCount = 120_000; // minimum recommended by OWASP for PBKDF2-HMAC-SHA512 (see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html #pbkdf2, captured 2022-02-18)
        //
        var saltLengthInBytes = (int)Math.Ceiling((double)saltNumberOfBits / 8.0);
        var hashLengthInBytes = (int)Math.Ceiling((double)hashNumberOfBits / 8.0);

        const int ITERATION_COUNT_BYTE_LENGTH = 4;
        var hashKeyDerivationIterationCountAsBytes = BitConversionUtils.GetBytesBE((uint)hashKeyDerivationIterationCount);
        if (hashKeyDerivationIterationCountAsBytes.Length != ITERATION_COUNT_BYTE_LENGTH)
        {
            throw new Exception("Programming error");
        }

        // generate a salt
        var salt = RandomNumberGenerator.GetBytes(saltLengthInBytes);

        // derive a subkey using PBKDF2 and HMACSHA512 (128-bit salt, 512-bit subkey)
        var hash = KeyDerivation.Pbkdf2(
            password: password,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA512,
            iterationCount: hashKeyDerivationIterationCount,
            numBytesRequested: hashLengthInBytes
        );

        // create the format marker
        byte formatMarker = (byte)HashAlgorithmMarker.PBkdf2WithHmacSha512_128bitSalt_512bitSubkey;

        var saltAndHash = new byte[1 /* formatMarker */ + ITERATION_COUNT_BYTE_LENGTH + salt.Length + hash.Length];
        saltAndHash[0] = formatMarker;
        Array.Copy(hashKeyDerivationIterationCountAsBytes, 0, saltAndHash, 1, ITERATION_COUNT_BYTE_LENGTH);
        Array.Copy(salt, 0, saltAndHash, 1 + ITERATION_COUNT_BYTE_LENGTH, salt.Length);
        Array.Copy(hash, 0, saltAndHash, 1 + ITERATION_COUNT_BYTE_LENGTH + salt.Length, hash.Length);

        return saltAndHash;
    }

    public static bool VerifyPasswordMatchesSaltAndHash(string password, byte[] saltAndHash)
    {
        const int ALGORITHM_MARKER_LENGTH = 1;
        if (saltAndHash.Length < ALGORITHM_MARKER_LENGTH)
        {
            System.Diagnostics.Debug.Assert(false, "Argument does not contain enough bytes to determine the hash algorithm and/or its parameters", nameof(saltAndHash));
            return false;
        }

        var algorithm = saltAndHash[0];
        switch ((HashAlgorithmMarker)algorithm)
        {
            case HashAlgorithmMarker.PBkdf2WithHmacSha512_128bitSalt_512bitSubkey:
                {
                    const int ITERATION_COUNT_BYTE_LENGTH = 4;
                    if (saltAndHash.Length < ALGORITHM_MARKER_LENGTH + ITERATION_COUNT_BYTE_LENGTH)
                    {
                        System.Diagnostics.Debug.Assert(false, "Argument does not contain enough bytes to determine the hash algorithm and/or its parameters", nameof(saltAndHash));
                        return false;
                    }

                    // settings for PBkdf2WithHmacSha512_128bitSalt_512bitSubkey
                    var saltNumberOfBits = 128; // minimum recommended by NIST (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf page 6, captured 2022-02-18)
                    var hashNumberOfBits = 512;

                    // extract the hash iteration count from the existing salt and hash // minimum recommended by OWASP for PBKDF2-HMAC-SHA512 (see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html - captured 2022-02-18)
                    var hashKeyDerivationIterationCountAsBytes = new byte[ITERATION_COUNT_BYTE_LENGTH];
                    Array.Copy(saltAndHash, 1, hashKeyDerivationIterationCountAsBytes, 0, ITERATION_COUNT_BYTE_LENGTH);
                    var hashKeyDerivationIterationCountAsUInt32 = BitConversionUtils.FromBytesBE_UInt32(hashKeyDerivationIterationCountAsBytes);
                    if (hashKeyDerivationIterationCountAsUInt32 > Int32.MaxValue)
                    {
                        throw new ArgumentException("Argument has an invalid iteration count (i.e. > int.MaxValue", nameof(saltAndHash));
                    }
                    var hashKeyDerivationIterationCount = (int)hashKeyDerivationIterationCountAsUInt32;

                    var saltLengthInBytes = (int)Math.Ceiling((double)saltNumberOfBits / 8.0);
                    var hashLengthInBytes = (int)Math.Ceiling((double)hashNumberOfBits / 8.0);

                    if (saltAndHash.Length != ALGORITHM_MARKER_LENGTH + ITERATION_COUNT_BYTE_LENGTH + saltLengthInBytes + hashLengthInBytes)
                    {
                        System.Diagnostics.Debug.Assert(false, "Argument does not contain correct number of bytes for its hash algorithm and its parameters", nameof(saltAndHash));
                        return false;
                    }

                    var salt = new byte[saltLengthInBytes];
                    var verifyHash = new byte[hashLengthInBytes];
                    Array.Copy(saltAndHash, ALGORITHM_MARKER_LENGTH + ITERATION_COUNT_BYTE_LENGTH, salt, 0, salt.Length);
                    Array.Copy(saltAndHash, ALGORITHM_MARKER_LENGTH + ITERATION_COUNT_BYTE_LENGTH + salt.Length, verifyHash, 0, verifyHash.Length);

                    // derive a subkey using PBKDF2 and HMACSHA512 (128-bit salt, 512-bit subkey)
                    var hash = KeyDerivation.Pbkdf2(
                        password: password,
                        salt: salt,
                        prf: KeyDerivationPrf.HMACSHA512,
                        iterationCount: hashKeyDerivationIterationCount,
                        numBytesRequested: hashLengthInBytes
                    );

                    // compare verifyHash with hash
                    var hashMatches = (verifyHash.SequenceEqual(hash) == false);

                    return hashMatches;
                }
            default:
                Debug.Assert(false, "Argument '" + nameof(saltAndHash) + " contains an unknown hash algorithm format marker.");
                return false;
        }
    }

    //

    public static async Task<string> DecryptPrefixedValueAsync_Throws(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string encryptedPrefixedValue)
    {
        var (prefix, encryptedValueWithoutPrefix) = PrefixUtils.SplitPrefixAndValue(encryptedPrefixedValue);

        var decryptedValueWithoutPrefix = await CryptoUtils.ConvertFromUrlBase64StringAndDecryptValueAsync_Throws(cryptoSecretsFunction, encryptedValueWithoutPrefix);

        var decryptedValue = PrefixUtils.CombinePrefixAndValue(prefix, decryptedValueWithoutPrefix);
        return decryptedValue;
    }

    public static async Task<string> EncryptPrefixedValueAsync_Throws(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string prefixedValue)
    {
        var (prefix, valueWithoutPrefix) = PrefixUtils.SplitPrefixAndValue(prefixedValue);

        var encryptedValueWithoutPrefix = await CryptoUtils.EncryptValueAndConvertToUrlBase64StringAsync_Throws(cryptoSecretsFunction, valueWithoutPrefix);

        var encryptedValue = PrefixUtils.CombinePrefixAndValue(prefix, encryptedValueWithoutPrefix);
        return encryptedValue;
    }

    public static async Task<string> ConvertFromUrlBase64StringAndDecryptValueAsync_Throws(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string encryptedValue)
    {
        var (aesKey, aesIV) = cryptoSecretsFunction();

        var decryptResult = await CryptoUtils.ConvertFromUrlBase64StringAndDecryptAsync(encryptedValue, aesKey, aesIV);
        if (decryptResult.IsError == true)
        {
            switch (decryptResult.Error!.Value)
            {
                case CryptoUtils.CryptoError.Values.CryptoFailure:
                    var ex = decryptResult.Error!.Exception!;
                    throw ex;
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var decryptedValue = decryptResult.Value!;

        return decryptedValue;
    }

    public static async Task<string> EncryptValueAndConvertToUrlBase64StringAsync_Throws(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string value)
    {
        var (aesKey, aesIV) = cryptoSecretsFunction();

        var encryptResult = await CryptoUtils.EncryptAndConvertToUrlBase64StringAsync(value, aesKey, aesIV);
        if (encryptResult.IsError == true)
        {
            switch (encryptResult.Error!.Value)
            {
                case CryptoUtils.CryptoError.Values.CryptoFailure:
                    var ex = encryptResult.Error!.Exception!;
                    throw ex;
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var encryptedValue = encryptResult.Value!;

        return encryptedValue;
    }

    //

    public static async Task<byte[]> LowercaseEncryptAndHashValueAsync_Throws(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string value)
    {
        var lowercasedValue = value.ToLowerInvariant();

        var result = await CryptoUtils.EncryptAndHashValueAsync_Throws(cryptoSecretsFunction, lowercasedValue);
        return result;
    }

    public static async Task<byte[]> EncryptAndHashValueAsync_Throws(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string value)
    {
        var encryptedValue = await CryptoUtils.EncryptAsync_Throws(value, cryptoSecretsFunction);

        var hash = CryptoUtils.HashValue(encryptedValue);

        return hash;
    }

    //

    public static byte[] HashValue(string value)
    {
        var valueAsBytes = System.Text.Encoding.UTF8.GetBytes(value);

        return CryptoUtils.HashValue(valueAsBytes);
    }

    public static byte[] HashValue(byte[] value)
    {
        // hash the value
        var hash = SHA512.HashData(value);

        return hash;
    }

}