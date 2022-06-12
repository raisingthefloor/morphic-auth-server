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
using Morphic.Core;
using System;
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

        var result = Convert.ToBase64String(memoryContents);
        return MorphicResult.OkResult(result);
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

    //

    private enum HashAlgorithmMarker: byte
    {
        PBkdf2WithHmacSha512_128bitSalt_512bitSubkey = 0x00,
    }

    public static string SaltAndHashPassword(string password)
    {
        // settings for PBkdf2WithHmacSha512_128bitSalt_512bitSubkey
        var saltNumberOfBits = 128; // minimum recommended by NIST (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf page 6, captured 2022-02-18)
        var hashNumberOfBits = 512; 
        var hashKeyDerivationIterationCount = 120_000; // minimum recommended by OWASP for PBKDF2-HMAC-SHA512 (see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html #pbkdf2, captured 2022-02-18)
        //
        var saltLengthInBytes = (int)Math.Ceiling((double)saltNumberOfBits / 8.0);
        var hashLengthInBytes = (int)Math.Ceiling((double)hashNumberOfBits / 8.0);

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

        var saltAndHash = new byte[1 /* formatMarker */ + salt.Length + hash.Length];
        saltAndHash[0] = formatMarker;
        Array.Copy(salt, 0, saltAndHash, 1, salt.Length);
        Array.Copy(hash, 0, saltAndHash, 1 + salt.Length, hash.Length);
        var base64SaltAndHash = Convert.ToBase64String(saltAndHash);

        return base64SaltAndHash;
    }

    public static bool VerifyPasswordMatchesSaltAndHash(string password, string base64SaltAndHash)
    {
        // settings for PBkdf2WithHmacSha512_128bitSalt_512bitSubkey
        var saltNumberOfBits = 128; // minimum recommended by NIST (see https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf page 6, captured 2022-02-18)
        var hashNumberOfBits = 512; 
        var hashKeyDerivationIterationCount = 120_000; // minimum recommended by OWASP for PBKDF2-HMAC-SHA512 (see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html - captured 2022-02-18)
        //
        var saltLengthInBytes = (int)Math.Ceiling((double)saltNumberOfBits / 8.0);
        var hashLengthInBytes = (int)Math.Ceiling((double)hashNumberOfBits / 8.0);

        var saltAndHash = Convert.FromBase64String(base64SaltAndHash);
        if (saltAndHash.Length < 1)
        {
            System.Diagnostics.Debug.Assert(false, "Argument 'base64SaltAndHash' does not contain enough bytes to determine the hash algorithm and/or its parameters");
            return false;
        }

        const int ALGORITHM_MARKER_LENGTH = 1;
        var algorithm = saltAndHash[0];
        nint algorithmParamsLength;
        switch ((HashAlgorithmMarker)algorithm)
        {
            case HashAlgorithmMarker.PBkdf2WithHmacSha512_128bitSalt_512bitSubkey:
                algorithmParamsLength = 0;
                break;
            default:
                System.Diagnostics.Debug.Assert(false, "Unknown hash algorithm");
                return false;
        }

        if (saltAndHash.Length != ALGORITHM_MARKER_LENGTH + algorithmParamsLength + saltLengthInBytes + hashLengthInBytes)
        {
            System.Diagnostics.Debug.Assert(false, "Argument 'base64SaltAndHash' does not contain the required number of data bytes for its algorithm");
            return false;
        }

        var salt = new byte[saltLengthInBytes];
        var verifyHash = new byte[hashLengthInBytes];
        Array.Copy(saltAndHash, ALGORITHM_MARKER_LENGTH, salt, 0, salt.Length);
        Array.Copy(saltAndHash, ALGORITHM_MARKER_LENGTH + salt.Length, verifyHash, 0, verifyHash.Length);

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
}