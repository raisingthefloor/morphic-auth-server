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

namespace MorphicAuthServer.Model;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;
using Morphic.Core;
using Morphic.Server.Core;
using System;
using System.Threading.Tasks;

public enum OAuthTokenType 
{
    [MorphicStringValue("accessToken")]
    AccessToken,
    [MorphicStringValue("initialAccessToken")]
    InitialAccessToken,
    [MorphicStringValue("registrationAccessToken")]
    RegistrationAccessToken,
}

internal class MongoSerializedOAuthToken 
{
    [BsonId]
    public string EncryptedId { get; init; }
    //
    [BsonElement("type")]
    public string Type { get; init; }
    //
    [BsonElement("owner"), BsonIgnoreIfNull]
    public string? Owner { get; init; }
    //
    [BsonElement("expires_at"), BsonIgnoreIfNull]
    public DateTime? ExpiresAt { get; init; }

    internal static async Task<MongoSerializedOAuthToken> FromAsync(OAuthToken oauthToken)
    {
        var encryptedId = await CryptoUtils.EncryptPrefixedValueAsync_Throws(AppSecrets.GetOAuthTokenIdCryptoKeyAndIVSecrets, oauthToken.Id);
        //
        string type = oauthToken.Type.ToStringValue()!;
        //
        string? owner = oauthToken.Owner;
        //
        DateTime? expiresAt = oauthToken.ExpiresAt is not null ? oauthToken.ExpiresAt.Value.UtcDateTime : null;

        var result = new MongoSerializedOAuthToken() 
        {
            EncryptedId = encryptedId,
            Type = type,
            Owner = owner,
            ExpiresAt = expiresAt,
        };
        return result;
    }
}


internal struct OAuthToken
{
    public string Id { get; init; }
    //
    public OAuthTokenType Type { get; init; }
    //
    public string? Owner { get; init; }
    //
    public DateTimeOffset? ExpiresAt { get; private set; }

    internal static async Task<MorphicResult<OAuthToken, MorphicUnit>> TryFromAsync(MongoSerializedOAuthToken mongoRecord) 
    {
        var id = await CryptoUtils.DecryptPrefixedValueAsync_Throws(AppSecrets.GetOAuthTokenIdCryptoKeyAndIVSecrets, mongoRecord.EncryptedId);
        //
        OAuthTokenType type;
        var nullableType = MorphicEnum<OAuthTokenType>.FromStringValue(mongoRecord.Type);
        if (nullableType is null) 
        {
            return MorphicResult.ErrorResult();
        }
        else 
        {
            type = nullableType!.Value;
        }
        //
        string? owner = mongoRecord.Owner;
        //
        DateTimeOffset? expiresAt = mongoRecord.ExpiresAt is not null ? (DateTimeOffset)mongoRecord.ExpiresAt : null;

        var result = new OAuthToken() 
        {
            Id = id,
            Type = type,
            Owner = owner,
            ExpiresAt = expiresAt,
        };
        return MorphicResult.OkResult(result);
    }

    internal OAuthToken(string id, OAuthTokenType type, string? owner) {
        this.Id = id;
        this.Type = type;
        this.Owner = owner;
        this.ExpiresAt = null;
    }

    //

    internal static async Task<MorphicResult<OAuthToken, LoadError>> LoadAsync(string id)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedOAuthToken> oauthTokenCollection;
        try 
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            oauthTokenCollection = authDatabase.GetCollection<MongoSerializedOAuthToken>("oauthtokens");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(ex));
        }

        var encryptedId = await CryptoUtils.EncryptPrefixedValueAsync_Throws(AppSecrets.GetOAuthTokenIdCryptoKeyAndIVSecrets, id);

        // attempt to load the token from MongoDB
        MongoSerializedOAuthToken mongoSerializedOAuthToken;
        try 
        {
            var filter = new BsonDocument { { "_id", encryptedId } };
            var mongoCursor = await oauthTokenCollection.FindAsync<MongoSerializedOAuthToken>(filter);
            try 
            {
                mongoSerializedOAuthToken = mongoCursor.Single();
            }
            catch 
            {
                return MorphicResult.ErrorResult(LoadError.NotFound);
            }
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(ex));
        }

        // return the newly-created oauth token
        var tryFromResult = await OAuthToken.TryFromAsync(mongoSerializedOAuthToken);
        if (tryFromResult.IsError == true) 
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(new FormatException()));
        }
        var oauthToken = tryFromResult.Value!;

        return MorphicResult.OkResult(oauthToken);
    }

    internal static async Task<MorphicResult<OAuthToken, CreateError>> CreateAsync(string regionId, OAuthTokenType tokenType, string? owner, DateTimeOffset? expiresAt)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedOAuthToken> oauthTokenCollection;
        try 
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            oauthTokenCollection = authDatabase.GetCollection<MongoSerializedOAuthToken>("oauthtokens");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(CreateError.DatabaseFailure(ex));
        }

        // generate a token (our regionId followed by a hyphen followed by a cryptographically generated id)
        string? id = null;
        //
        // save the token record in MongoDB; if the token's id already exists, generate a new one and try again (up to MAX_RETRIES number of times)
        nint remainingUniqueIdRetries = 32; // NOTE: it is extremely unlikely that we'd ever generate collisions several times in a row, but this code is here to guard against that extremely unlikely edge case (to prevent a runaway loop)
        while (remainingUniqueIdRetries > 0)
        {
            // create our registration record (to save to MongoDB)
            id = regionId + "-" + CryptoUtils.GenerateCryptoRandomUrlEncodeSafeString(/*bits: */256);
            var oauthTokenRecord = await MongoSerializedOAuthToken.FromAsync(
                new OAuthToken(id, tokenType, owner)
                {
                    ExpiresAt = expiresAt?.UtcDateTime,
                }
            );

            // attempt to save the token record to MongoDB
            // NOTE: we specifically request that we only insert (create) a _new_ record--and not overwrite/upsert an existing one--so that we get an error if there's an id (token) collision
            try 
            {
                await oauthTokenCollection.InsertOneAsync(oauthTokenRecord);

                // if the operation was successful, break out of our loop
                break;
            }
            catch (MongoWriteException ex) 
            {
                if (ex.WriteError.Category == ServerErrorCategory.DuplicateKey) 
                {
                    // retry, using a different (new) token id; don't return this error to the caller
                }
                else 
                {
                    // for any other MongoWriteException, bubble this error up to our caller
                    return MorphicResult.ErrorResult(CreateError.DatabaseFailure(ex));
                }
            }
            catch (Exception ex)
            {
                return MorphicResult.ErrorResult(CreateError.DatabaseFailure(ex));
            }

            remainingUniqueIdRetries -= 1;
        }

        // if we were unsuccessful in generating a unique token id, fail now
        if (remainingUniqueIdRetries <= 0)
        {
            // we tried generating token ids repeatedly and kept getting collisions; return this error to the caller for diagnostics/debugging
            // NOTE: we may want to create a separate error for this condition (although 'cryptography failed' seems to be appropriate, given the unlikelihood of dozens of unique token id collisions in our database)
            return MorphicResult.ErrorResult(CreateError.CryptographyFailed);
        }

        // return the newly-created oauth token
        var oauthToken = new OAuthToken(id!, tokenType, owner)
        {
            ExpiresAt = expiresAt
        };

        return MorphicResult.OkResult(oauthToken);
    }

}
