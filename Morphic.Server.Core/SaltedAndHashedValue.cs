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

namespace Morphic.Server.Core;

public struct SaltedAndHashedValue
{
    private string? _cleartextValue { get; init; }
    //
    private byte[] _saltedHashAsBytes { get; init; }

    private SaltedAndHashedValue(string? value, byte[] saltedHashAsBytes)
    {
        _cleartextValue = value;
        _saltedHashAsBytes = saltedHashAsBytes;
    }

    public static SaltedAndHashedValue FromCleartextValue(string value)
    {
        var result = new SaltedAndHashedValue(value, CryptoUtils.SaltAndHashPassword(value));
        return result;
    }

    public static SaltedAndHashedValue FromSaltedAndHashedValue(byte[] saltedHashAsBytes)
    {
        var result = new SaltedAndHashedValue(null, saltedHashAsBytes);
        return result;
    }

    public bool ConfirmPasswordMatch(string value)
    {
        return CryptoUtils.VerifyPasswordMatchesSaltAndHash(value, _saltedHashAsBytes);
    }

    public bool HasCleartextValue
    {
        get 
        {
            return (_cleartextValue is not null);
        }
    }

    public string? CleartextValue
    {
        get
        {
            return _cleartextValue;
        }
    }

    public byte[] SaltedHashAsBytes
    {
        get
        {
            return _saltedHashAsBytes;
        }
    }

}