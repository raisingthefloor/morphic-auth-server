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

namespace MorphicAuthServer.Model.UserCredentialDataObjects;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using Morphic.Core;
using Morphic.Server.Core;
using System;
using System.Threading.Tasks;

internal record PasswordUserCredentialData : IUserCredentialData
{
    //[BsonElement("hashed_password")]
    public SaltedAndHashedValue HashedPassword { get; init; }
    
    public PasswordUserCredentialData(SaltedAndHashedValue hashedPassword)
    {
        this.HashedPassword = hashedPassword;
    }

    public BsonDocument ToBsonDocument()
    {
        var result = new BsonDocument();

        result.Add("hashed_password", this.HashedPassword.SaltedHashAsBytes);

        return result;
    }

    internal static MorphicResult<PasswordUserCredentialData, MorphicUnit> TryFrom(BsonDocument bsonDocument)
    {
        if (bsonDocument.Contains("hashed_password") == false)
        {
            return MorphicResult.ErrorResult();
        }
        var hashedPasswordValue = (byte[])bsonDocument.GetElement("hashed_password").Value;

        var hashedPassword = SaltedAndHashedValue.FromSaltedAndHashedValue(hashedPasswordValue);

        var result = new PasswordUserCredentialData(hashedPassword);
        return MorphicResult.OkResult(result);
    }
}
