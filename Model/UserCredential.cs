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
using MorphicAuthServer.Model.UserCredentialDataObjects;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

internal record MongoSerializedUserCredential
{
    [BsonId]
    public string Id { get; set; }
    //
    [BsonElement("user_id")]
    public string UserId { get; set; }
    //
    [BsonElement("type")]
    public string Type { get; set; }
    //
    [BsonElement("data")]
    public BsonDocument Data { get; set; }

    internal static MongoSerializedUserCredential From(UserCredential userCredential)
    {
        var id = userCredential.Id;
        //
        var userId = userCredential.UserId;
        //
        string type = userCredential.Type;
        //
        BsonDocument data;
        switch (type)
        {
            case "password":
                data = userCredential.Data.ToBsonDocument();
                break;
            default:
                // NOTE: as we create the UserCredential objects, no other cases should ever be encountered
                throw new NotSupportedException();
        }

        var result = new MongoSerializedUserCredential()
        {
            Id = id,
            UserId = userId,
            Type = type,
            Data = data,
        };
        return result;
    }
}


internal struct UserCredential
{
    public string Id { get; set; }
    //
    public string UserId { get; set; }
    //
    public string Type { get; set; }
    //
    public IUserCredentialData Data { get; set; }

    internal static MorphicResult<UserCredential, MorphicUnit> TryFrom(MongoSerializedUserCredential mongoRecord)
    {
        var id = mongoRecord.Id;
        //
        var userId = mongoRecord.UserId;
        //
        string type = mongoRecord.Type;
        //
        IUserCredentialData data;
        switch (type)
        {
            case "password":
                { 
                    var tryFromResult = PasswordUserCredentialData.TryFrom(mongoRecord.Data);
                    if (tryFromResult.IsError)
                    {
                        return MorphicResult.ErrorResult();
                    }
                    data = tryFromResult.Value!;
                }
                break;
            default:
                return MorphicResult.ErrorResult();
        }

        var result = new UserCredential()
        {
            Id = id,
            UserId = userId,
            Type = type,
            Data = data,
        };
        return MorphicResult.OkResult(result);
    }

    internal UserCredential(string id, string userId, string type, IUserCredentialData data)
    {
        this.Id = id;
        this.UserId = userId;
        this.Type = type;
        this.Data = data;
    }

    //

    internal static async Task<MorphicResult<UserCredential, LoadError>> LoadAsync(string id)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedUserCredential> userCredentialCollection;
        try
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            userCredentialCollection = authDatabase.GetCollection<MongoSerializedUserCredential>("user_credentials");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(ex));
        }

        // attempt to load the user credential from MongoDB
        MongoSerializedUserCredential mongoSerializedUserCredential;
        try
        {
            var filter = new BsonDocument { { "_id", id } };
            var mongoCursor = await userCredentialCollection.FindAsync<MongoSerializedUserCredential>(filter);
            try
            {
                mongoSerializedUserCredential = mongoCursor.Single();
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

        // return the newly-created user credential
        var tryFromResult = UserCredential.TryFrom(mongoSerializedUserCredential);
        if (tryFromResult.IsError == true)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(new FormatException()));
        }
        var userCredential = tryFromResult.Value!;

        return MorphicResult.OkResult(userCredential);
    }

    internal static async Task<MorphicResult<List<UserCredential>, LoadError>> LoadAllForUserAsync(string userId)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedUserCredential> userCredentialCollection;
        try
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            userCredentialCollection = authDatabase.GetCollection<MongoSerializedUserCredential>("user_credentials");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(ex));
        }

        // attempt to load the user credential from MongoDB
        List<MongoSerializedUserCredential> mongoSerializedUserCredentials;
        try
        {
            var filter = new BsonDocument { { "user_id", userId } };
            var mongoCursor = await userCredentialCollection.FindAsync<MongoSerializedUserCredential>(filter);
            try
            {
                mongoSerializedUserCredentials = mongoCursor.ToList();
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

        // return the newly-created user credentials
        List<UserCredential> userCredentials = new();
        foreach (var mongoSerializedUserCredential in mongoSerializedUserCredentials) 
        {
            var tryFromResult = UserCredential.TryFrom(mongoSerializedUserCredential);
            if (tryFromResult.IsError == true)
            {
                return MorphicResult.ErrorResult(LoadError.DatabaseFailure(new FormatException()));
            }
            var userCredential = tryFromResult.Value!;

            userCredentials.Add(userCredential);
        }

        return MorphicResult.OkResult(userCredentials);
    }

    internal static async Task<MorphicResult<UserCredential, CreateError>> CreateAsync(string regionId, string userId, string type, IUserCredentialData data)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedUserCredential> userCredentialsCollection;
        try
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            userCredentialsCollection = authDatabase.GetCollection<MongoSerializedUserCredential>("user_credentials");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(CreateError.DatabaseFailure(ex));
        }

        // generate a user credential id (our regionId followed by a hyphen followed by a guid)
        string? id = null;
        //
        // save the user credential record in MongoDB; if the user credential's id already exists, generate a new one and try again (up to MAX_RETRIES number of times)
        nint remainingUniqueIdRetries = 32; // NOTE: it is extremely unlikely that we'd ever generate collisions several times in a row, but this code is here to guard against that extremely unlikely edge case (to prevent a runaway loop)
        while (remainingUniqueIdRetries > 0)
        {
            // create our registration record (to save to MongoDB)
            id = regionId + "-" + Guid.NewGuid().ToString("N");
            var userCredentialRecord = MongoSerializedUserCredential.From(
                new UserCredential(id, userId, type, data)
                {
                }
            );

            // attempt to save the user credential record to MongoDB
            // NOTE: we specifically request that we only insert (create) a _new_ record--and not overwrite/upsert an existing one--so that we get an error if there's an id (user credential) collision
            try
            {
                await userCredentialsCollection.InsertOneAsync(userCredentialRecord);

                // if the operation was successful, break out of our loop
                break;
            }
            catch (MongoWriteException ex)
            {
                if (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
                {
                    // retry, using a different (new) user credential id; don't return this error to the caller
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

        // if we were unsuccessful in generating a unique user credential id, fail now
        if (remainingUniqueIdRetries <= 0)
        {
            // we tried generating user credential ids repeatedly and kept getting collisions; return this error to the caller for diagnostics/debugging
            // NOTE: we may want to create a separate error for this condition (although 'cryptography failed' seems to be appropriate, given the unlikelihood of dozens of unique user credential id collisions in our database)
            return MorphicResult.ErrorResult(CreateError.CryptographyFailed);
        }

        // return the newly-created user
        var userCredential = new UserCredential(id!, userId, type, data)
        {
        };

        return MorphicResult.OkResult(userCredential);
    }
}
