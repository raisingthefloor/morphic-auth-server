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
        // capture the necessary secret to encrypt/decrypt oauth token ids
        var oauthTokenIdEncryptionKeyAsBase64String = Morphic.Server.Settings.MorphicAppSecret.GetSecret("auth-server", "OAUTHTOKEN_ID_ENCRYPTION_KEY");
        if (oauthTokenIdEncryptionKeyAsBase64String is null) { throw new Exception("Application secret auth-server/OAUTHTOKEN_ID_ENCRYPTION_KEY was not found."); }
        var oauthTokenIdEncryptionKey = Convert.FromBase64String(oauthTokenIdEncryptionKeyAsBase64String!);
        //
        var oauthTokenIdEncryptionIVAsBase64String = Morphic.Server.Settings.MorphicAppSecret.GetSecret("auth-server", "OAUTHTOKEN_ID_ENCRYPTION_IV");
        if (oauthTokenIdEncryptionIVAsBase64String is null) { throw new Exception("Application secret auth-server/OAUTHTOKEN_ID_ENCRYPTION_IV was not found."); }
        var oauthTokenIdEncryptionIV = Convert.FromBase64String(oauthTokenIdEncryptionIVAsBase64String!);

        return (oauthTokenIdEncryptionKey, oauthTokenIdEncryptionIV);
    }
}
