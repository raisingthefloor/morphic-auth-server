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

namespace MorphicAuthServer.Model;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;
using Morphic.Core;
using Morphic.Server.Core;
using System;
using System.Threading.Tasks;

internal class MongoSerializedUserEmailAddress
{
    [BsonElement("encrypted_value")]
    public byte[] EncryptedValue { get; init; }
    //
    [BsonElement("case_insensitive_hash")]
    public byte[] CaseInsensitiveHash { get; init; }

    private MongoSerializedUserEmailAddress(byte[] encryptedValue, byte[] caseInsensitiveHash)
    {
        this.EncryptedValue = encryptedValue;
        this.CaseInsensitiveHash = caseInsensitiveHash;
    }

    public static async Task<MongoSerializedUserEmailAddress> FromAsync(UserEmailAddress userEmailAddress)
    {
        var encryptedValue = await CryptoUtils.EncryptAsync_Throws(userEmailAddress.Value, AppSecrets.GetUserEmailAddressValueCryptoKeyAndIVSecrets);
        //
        var caseInsensitiveHash = await CryptoUtils.LowercaseEncryptAndHashValueAsync_Throws(AppSecrets.GetUserEmailAddressValueCryptoKeyAndIVSecrets, userEmailAddress.Value);

        var result = new MongoSerializedUserEmailAddress(encryptedValue, caseInsensitiveHash);
        return result;
    }
}

internal class MongoSerializedUser
{
    [BsonId]
    public string Id { get; init; }
    //
    [BsonElement("email_address"), BsonIgnoreIfNull]
    public MongoSerializedUserEmailAddress? EmailAddress { get; init; }

    internal static async Task<MongoSerializedUser> FromAsync(User user)
    {
        var id = user.Id;
        //
        MongoSerializedUserEmailAddress? emailAddress;
        if (user.EmailAddress is not null)
        {
            emailAddress = await MongoSerializedUserEmailAddress.FromAsync(user.EmailAddress);
        }
        else
        {
            emailAddress = null;
        }

        var result = new MongoSerializedUser()
        {
            Id = id,
            EmailAddress = emailAddress,
        };
        return result;
    }
}

internal class UserEmailAddress
{
    public string Value { get; init; }

    public UserEmailAddress(string value)
    {
        this.Value = value;
    }

    public static async Task<UserEmailAddress> FromAsync(MongoSerializedUserEmailAddress mongoRecord)
    {
        var value = await CryptoUtils.DecryptAsync_Throws(mongoRecord.EncryptedValue, AppSecrets.GetUserEmailAddressValueCryptoKeyAndIVSecrets);

        var result = new UserEmailAddress(value);
        return result;
    }
}


internal struct User
{
    public string Id { get; init; }
    //
    public UserEmailAddress? EmailAddress { get; init; }

    internal static async Task<MorphicResult<User, MorphicUnit>> TryFromAsync(MongoSerializedUser mongoRecord)
    {
        var id = mongoRecord.Id;
        //
        UserEmailAddress? emailAddress;
        if (mongoRecord.EmailAddress is not null)
        {
            emailAddress = await UserEmailAddress.FromAsync(mongoRecord.EmailAddress);
        }
        else
        {
            emailAddress = null;
        }

        var result = new User()
        {
            Id = id,
            EmailAddress = emailAddress,
        };
        return MorphicResult.OkResult(result);
    }

    internal User(string id, UserEmailAddress? emailAddress)
    {
        this.Id = id;
        this.EmailAddress = emailAddress;
    }

    //

    internal static async Task<MorphicResult<User, LoadError>> LoadAsync(string id)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedUser> userCollection;
        try
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            userCollection = authDatabase.GetCollection<MongoSerializedUser>("users");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(ex));
        }

        // attempt to load the user from MongoDB
        MongoSerializedUser mongoSerializedUser;
        try
        {
            var filter = new BsonDocument { { "_id", id } };
            var mongoCursor = await userCollection.FindAsync<MongoSerializedUser>(filter);
            try
            {
                mongoSerializedUser = mongoCursor.Single();
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

        // return the newly-created user
        var tryFromResult = await User.TryFromAsync(mongoSerializedUser);
        if (tryFromResult.IsError == true)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(new FormatException()));
        }
        var user = tryFromResult.Value!;

        return MorphicResult.OkResult(user);
    }

    internal static async Task<MorphicResult<User, LoadError>> LoadAsync(UserEmailAddress emailAddress)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedUser> userCollection;
        try
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            userCollection = authDatabase.GetCollection<MongoSerializedUser>("users");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(ex));
        }

        // convert the email address to a case-insensitive hash
        var mongoSerializedUserEmailAddress = await MongoSerializedUserEmailAddress.FromAsync(emailAddress)!;

        // attempt to load the user from MongoDB
        MongoSerializedUser mongoSerializedUser;
        try
        {
            var filter = new BsonDocument { { "email_address.case_insensitive_hash", mongoSerializedUserEmailAddress.CaseInsensitiveHash } };
            var mongoCursor = await userCollection.FindAsync<MongoSerializedUser>(filter);
            try
            {
                mongoSerializedUser = mongoCursor.Single();
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

        // return the newly-created user
        var tryFromResult = await User.TryFromAsync(mongoSerializedUser);
        if (tryFromResult.IsError == true)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(new FormatException()));
        }
        var user = tryFromResult.Value!;

        return MorphicResult.OkResult(user);
    }

    internal static async Task<MorphicResult<User, CreateError>> CreateAsync(string regionId, UserEmailAddress? emailAddress)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedUser> userCollection;
        try
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            userCollection = authDatabase.GetCollection<MongoSerializedUser>("users");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(CreateError.DatabaseFailure(ex));
        }

        // generate a user id (our regionId followed by a hyphen followed by a guid)
        string? id = null;
        //
        // save the user record in MongoDB; if the user's id already exists, generate a new one and try again (up to MAX_RETRIES number of times)
        nint remainingUniqueIdRetries = 32; // NOTE: it is extremely unlikely that we'd ever generate collisions several times in a row, but this code is here to guard against that extremely unlikely edge case (to prevent a runaway loop)
        while (remainingUniqueIdRetries > 0)
        {
            // create our registration record (to save to MongoDB)
            id = regionId + "-" + Guid.NewGuid().ToString("N");
            var userRecord = await MongoSerializedUser.FromAsync(
                new User(id, emailAddress)
                {
                }
            );

            // attempt to save the user record to MongoDB
            // NOTE: we specifically request that we only insert (create) a _new_ record--and not overwrite/upsert an existing one--so that we get an error if there's an id (user) collision
            try
            {
                await userCollection.InsertOneAsync(userRecord);

                // if the operation was successful, break out of our loop
                break;
            }
            catch (MongoWriteException ex)
            {
                if (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
                {
                    // retry, using a different (new) user id; don't return this error to the caller
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

        // if we were unsuccessful in generating a unique user id, fail now
        if (remainingUniqueIdRetries <= 0)
        {
            // we tried generating user ids repeatedly and kept getting collisions; return this error to the caller for diagnostics/debugging
            // NOTE: we may want to create a separate error for this condition (although 'cryptography failed' seems to be appropriate, given the unlikelihood of dozens of unique user id collisions in our database)
            return MorphicResult.ErrorResult(CreateError.CryptographyFailed);
        }

        // return the newly-created user
        var user = new User(id!, emailAddress)
        {
        };

        return MorphicResult.OkResult(user);
    }
}
