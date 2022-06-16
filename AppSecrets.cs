// Copyright 2021-2022 Raising the Floor - US, Inc.
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

using System;

namespace MorphicAuthServer;

internal class AppSecrets
{
    public static string GetMongoDbAuthConnectionStringSecret()
    {
        var mongoDbConnectionString = Morphic.Server.Settings.MorphicAppSecret.GetSecret("auth-server", "MONGO_CONNECTION_STRING");
        if (mongoDbConnectionString is null) { throw new Exception("Application secret auth-server/MONGO_CONNECTION_STRING was not found."); }

        return mongoDbConnectionString!;
    }

    //

    public static (byte[], byte[]) GetOAuthTokenIdCryptoKeyAndIVSecrets()
    {
        return AppSecrets.GetCryptoKeyAndIVSecrets("auth-server", "OAUTHTOKEN_ID_ENCRYPTION_KEY", "OAUTHTOKEN_ID_ENCRYPTION_IV");
    }

    public static (byte[], byte[]) GetUserEmailAddressValueCryptoKeyAndIVSecrets()
    {
        return AppSecrets.GetCryptoKeyAndIVSecrets("auth-server", "USER_EMAILADDRESS_VALUE_ENCRYPTION_KEY", "USER_EMAILADDRESS_VALUE_ENCRYPTION_IV");
    }

    public static (byte[], byte[]) GetCryptoKeyAndIVSecrets(string secretGroup, string secretKeyForCryptoKey, string secretKeyForCryptoIv)
    {
        // capture the necessary secret to encrypt/decrypt user email addresses
        var encryptionKeyAsBase64String = Morphic.Server.Settings.MorphicAppSecret.GetSecret(secretGroup, secretKeyForCryptoKey);
        if (encryptionKeyAsBase64String is null) { throw new Exception("Application secret " + secretGroup + "/" + secretKeyForCryptoKey + " was not found."); }
        var encryptionKey = Convert.FromBase64String(encryptionKeyAsBase64String!);
        //
        var cryptoIVAsBase64String = Morphic.Server.Settings.MorphicAppSecret.GetSecret(secretGroup, secretKeyForCryptoIv);
        if (cryptoIVAsBase64String is null) { throw new Exception("Application secret " + secretGroup  + "/" + secretKeyForCryptoIv + " was not found."); }
        var cryptoIV = Convert.FromBase64String(cryptoIVAsBase64String!);

        return (encryptionKey, cryptoIV);
    }
}
