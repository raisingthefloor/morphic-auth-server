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

using Morphic.Core;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Morphic.Server.Core;

public struct CaseInsensitiveHashedValue
{
    private Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate _cryptoSecretsFunction { get; init; }
    //
    private string? _cleartext { get; init; }
    //
    // NOTE: _caseInsensitiveHash is created by lowercasing, encrypting and then hashing the cleartext
    private byte[] _caseInsensitiveHash { get; init; }

    private CaseInsensitiveHashedValue(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string? cleartext, byte[] caseInsensitiveHash)
    {
        _cryptoSecretsFunction = cryptoSecretsFunction;
        _cleartext = cleartext;
        _caseInsensitiveHash = caseInsensitiveHash;
    }
    
    public static async Task<CaseInsensitiveHashedValue> FromCleartextValueAsync(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, string cleartext)
    {
        var caseInsensitiveHash = await CryptoUtils.LowercaseEncryptAndHashValueAsync_Throws(cryptoSecretsFunction, cleartext);
        
        var result = new CaseInsensitiveHashedValue(cryptoSecretsFunction, cleartext, caseInsensitiveHash);

        return result;
    }

    public static CaseInsensitiveHashedValue FromHashedValue(Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate cryptoSecretsFunction, byte[] caseInsensitiveHash)
    {
        var result = new CaseInsensitiveHashedValue(cryptoSecretsFunction, null, caseInsensitiveHash);
        return result;
    }

    public async Task<bool> ConfirmCleartextMatchAsync(string cleartext)
    {
        var compareHashAsBytes = await CryptoUtils.LowercaseEncryptAndHashValueAsync_Throws(_cryptoSecretsFunction, cleartext);
        return compareHashAsBytes.SequenceEqual(_caseInsensitiveHash);
    }

    public bool HasCleartext
    {
        get
        {
            return (_cleartext is not null);
        }
    }

    public Morphic.Server.Settings.MorphicAppSecret.GetCryptoKeyAndIVSecretsDelegate CryptoSecretsFunction
    {
        get
        {
            return _cryptoSecretsFunction;
        }
    }

    public string? Cleartext
    {
        get
        {
            return _cleartext;
        }
    }

    public byte[] CaseInsensitiveHash
    {
        get
        {
            return _caseInsensitiveHash;
        }
    }
}