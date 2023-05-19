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
using Morphic.OAuth;
using Morphic.Server.Core;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

internal class MongoSerializedOAuthClientSecret
{
    [BsonElement("hashed_value")]
    public byte[] HashedValue { get; init; }
    //
    [BsonElement("expires_at"), BsonIgnoreIfNull]
    public DateTime? ExpiresAt { get; init; }

    public MongoSerializedOAuthClientSecret(byte[] hashedValue)
    {
        this.HashedValue = hashedValue;
    }

    public static MongoSerializedOAuthClientSecret From(OAuthClientSecret oauthClientSecret)
    {
        var hashedValue = oauthClientSecret.HashedValue.SaltedHashAsBytes;
        //
        var expiresAt = oauthClientSecret.ExpiresAt;

        var result = new MongoSerializedOAuthClientSecret(hashedValue)
        {
            ExpiresAt = expiresAt?.UtcDateTime,
        };
        return result;
    }
}

internal class MongoSerializedOAuthClient 
{
    [BsonId]
    public string ClientId { get; init; }
    //
    // NOTE: only one "client secret" is the active one at any time; we keep up to two in case the refreshed secret gets lost (and then we purge the oldest secret when the newest one is used)
    [BsonElement("secrets"), BsonIgnoreIfNull]
    public List<MongoSerializedOAuthClientSecret>? ClientSecrets { get; init; }
    //
    [BsonElement("issued_at"), BsonIgnoreIfNull]
    public DateTime? ClientIdIssuedAt { get; init; }

    [BsonElement("encrypted_registration_access_tokens"), BsonIgnoreIfNull]
    public List<string>? EncryptedRegistrationAccessTokens { get; init; }

    [BsonElement("registered_metadata")] 
    public MongoSerializedOAuthClientMetadata RegisteredMetadata { get; init; }

    internal static async Task<MongoSerializedOAuthClient> FromAsync(OAuthClient oauthClient)
    {
        var clientId = oauthClient.ClientId;
        //
        List<MongoSerializedOAuthClientSecret>? clientSecrets = null;
        if (oauthClient.ClientSecrets is not null)
        {
            clientSecrets = new();
            foreach (var clientSecret in oauthClient.ClientSecrets)
            {
                clientSecrets.Add(MongoSerializedOAuthClientSecret.From(clientSecret));
            }
        }
        //
        DateTime? clientIdIssuedAt = oauthClient.ClientIdIssuedAt is not null ? oauthClient.ClientIdIssuedAt.Value.UtcDateTime : null;
        //
        List<string>? encryptedRegistrationAccessTokens = null;
        if (oauthClient.RegistrationAccessTokens is not null)
        {
            encryptedRegistrationAccessTokens = new();
            foreach (var registrationAccessToken in oauthClient.RegistrationAccessTokens)
            {
                var encryptedRegistrationAccessToken = await CryptoUtils.EncryptPrefixedValueAsync_Throws(AppSecrets.GetOAuthTokenIdCryptoKeyAndIVSecrets, registrationAccessToken);
                encryptedRegistrationAccessTokens.Add(encryptedRegistrationAccessToken);
            }
        }
        //
        var registeredMetadata = MongoSerializedOAuthClientMetadata.From(oauthClient.RegisteredMetadata);

        var result = new MongoSerializedOAuthClient() 
        {
            ClientId = clientId,
            ClientSecrets = clientSecrets,
            ClientIdIssuedAt = clientIdIssuedAt,
            EncryptedRegistrationAccessTokens = encryptedRegistrationAccessTokens,
            RegisteredMetadata = registeredMetadata,
        };
        return result;
    }
}

internal class OAuthClientSecret 
{
    public SaltedAndHashedValue HashedValue { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }

    public OAuthClientSecret(SaltedAndHashedValue hashedValue) 
    {
        this.HashedValue = hashedValue;
    }

    public static OAuthClientSecret From(MongoSerializedOAuthClientSecret mongoRecord)
    {
        var hashedValue = SaltedAndHashedValue.FromSaltedAndHashedValue(mongoRecord.HashedValue);
        //
        DateTimeOffset? expiresAt = (mongoRecord.ExpiresAt is not null) ? (DateTimeOffset)mongoRecord.ExpiresAt : null;

        var result = new OAuthClientSecret(hashedValue)
        {
            ExpiresAt = expiresAt
        };
        return result;
    }
}

internal class OAuthClient
{
    public string ClientId { get; init; }
    //
    public List<OAuthClientSecret>? ClientSecrets { get; init; }
    //
    public DateTimeOffset? ClientIdIssuedAt { get; init; }

    public List<string>? RegistrationAccessTokens { get; init; }

    public OAuthClientMetadata RegisteredMetadata { get; init; }

    internal static async Task<MorphicResult<OAuthClient, MorphicUnit>> TryFromAsync(MongoSerializedOAuthClient mongoRecord) 
    {
        var clientId = mongoRecord.ClientId;
        //
        List<OAuthClientSecret>? clientSecrets = null;
        if (mongoRecord.ClientSecrets is not null)
        {
            clientSecrets = new();
            foreach (var mongoSerializedClientSecret in mongoRecord.ClientSecrets)
            {
                clientSecrets.Add(OAuthClientSecret.From(mongoSerializedClientSecret));
            }
        }
        //
        DateTimeOffset? clientIdIssuedAt = mongoRecord.ClientIdIssuedAt is not null ? (DateTimeOffset)mongoRecord.ClientIdIssuedAt : null;
        //
        List<string>? registrationAccessTokens = null;
        if (mongoRecord.EncryptedRegistrationAccessTokens is not null)
        {
            registrationAccessTokens = new();
            foreach (var encryptedRegistrationAccessToken in mongoRecord.EncryptedRegistrationAccessTokens)
            {
                var registrationAccessToken = await CryptoUtils.DecryptPrefixedValueAsync_Throws(AppSecrets.GetOAuthTokenIdCryptoKeyAndIVSecrets, encryptedRegistrationAccessToken);
                registrationAccessTokens.Add(registrationAccessToken);
            }
        }
        //
        var tryFromResult = OAuthClientMetadata.TryFrom(mongoRecord.RegisteredMetadata);
        if (tryFromResult.IsError) {
            return MorphicResult.ErrorResult();
        }
        var registeredMetadata = tryFromResult.Value!;

        var result = new OAuthClient(clientId) 
        {
            ClientSecrets = clientSecrets,
            ClientIdIssuedAt = clientIdIssuedAt,
            RegistrationAccessTokens = registrationAccessTokens,
            RegisteredMetadata = registeredMetadata
        };
        return MorphicResult.OkResult(result);
    }

    //

    internal OAuthClient(string clientId)
    {
        this.ClientId = clientId;
        this.RegisteredMetadata = new OAuthClientMetadata();
    }

    //

    internal static async Task<MorphicResult<OAuthClient, LoadError>> LoadAsync(string clientId)
    {
        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedOAuthClient> oauthClientCollection;
        try 
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            oauthClientCollection = authDatabase.GetCollection<MongoSerializedOAuthClient>("oauthclients");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(ex));
        }

        // attempt to load the client from MongoDB
        MongoSerializedOAuthClient mongoSerializedOAuthClient;
        try 
        {
            var filter = new BsonDocument { { "_id", clientId } };
            var mongoCursor = await oauthClientCollection.FindAsync<MongoSerializedOAuthClient>(filter);
            try 
            {
                mongoSerializedOAuthClient = mongoCursor.Single();
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

        // return the newly-created oauth client
        var tryFromResult = await OAuthClient.TryFromAsync(mongoSerializedOAuthClient);
        if (tryFromResult.IsError == true) 
        {
            return MorphicResult.ErrorResult(LoadError.DatabaseFailure(new FormatException()));
        }
        var oauthClient = tryFromResult.Value!;

        return MorphicResult.OkResult(oauthClient);
    }

    internal static async Task<MorphicResult<OAuthClient, CreateError>> CreateAsync(OAuthClientMetadata metadata, string regionId)
    {
        // verify that the region id can be parsed as an unsigned number
        if (UInt32.TryParse(regionId, out var regionIdAsUInt32) == false) {
            throw new ArgumentOutOfRangeException(nameof(regionId));
        }
        
        // NOTE: although our client metadata should have already been sanitized, double-check that the provided metadata is valid for this server
        var validateResult = OAuthClient.ValidateMetadata(metadata);
        if (validateResult.IsError == true)
        {
            // NOTE: it is the caller's responsibility to make sure that input is fully validated before passing it to this function; we pass the validation result along as a courtesy--but it's a nullable object (to allow for flow-through CreateError failures) so it might not be useful
            return MorphicResult.ErrorResult(CreateError.ValidationFailed(validateResult.Error!));
        }

        // assign an "issued" time
        var clientIdIssuedAt = DateTime.UtcNow;

        // NOTE: in our current implementation, client secrets expire after 90 days; this provides us with a data point to clean up client registration records after some time
        var secretExpirationDuration = new TimeSpan(90, 0, 0, 0);

        // generate a client secret (if required for this client)
        string? clientSecret;
        DateTime? clientSecretExpiresAt;
        //
        switch (metadata.TokenEndpointAuthMethod)
        {
            case OAuthTokenEndpointAuthMethod.ClientSecretBasic:
            case OAuthTokenEndpointAuthMethod.ClientSecretPost:
                clientSecret = CryptoUtils.GenerateCryptoRandomUrlEncodeSafeString(/*bits: */256);
                clientSecretExpiresAt = clientIdIssuedAt.Add(secretExpirationDuration);
                break;
            case OAuthTokenEndpointAuthMethod.None:
            default:
                clientSecret = null;
                clientSecretExpiresAt = null;
                break;
        }

        List<OAuthClientSecret>? clientSecrets = null;
        if (clientSecret is not null) 
        {
            clientSecrets = new();
            var oauthClientSecret = new OAuthClientSecret(hashedValue: SaltedAndHashedValue.FromCleartextValue(clientSecret))
            {
                ExpiresAt = clientSecretExpiresAt
            };
            clientSecrets.Add(oauthClientSecret);
        }

        // connect to MongoDB
        var mongoConnectionString = MorphicAuthServer.AppSecrets.GetMongoDbAuthConnectionStringSecret();
        //
        MongoClient mongoClient;
        IMongoDatabase authDatabase;
        IMongoCollection<MongoSerializedOAuthClient> oauthClientCollection;
        try 
        {
            mongoClient = new MongoClient(mongoConnectionString);
            authDatabase = mongoClient.GetDatabase("auth");
            oauthClientCollection = authDatabase.GetCollection<MongoSerializedOAuthClient>("oauthclients");
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(CreateError.DatabaseFailure(ex));
        }

        // generate a client ID (our regionId followed by a hyphen followed by a cryptographically generated id)
        string? clientId = null;
        //
        // save the client registration record in MongoDB; if the clientID already exists, generate a new one and try again (up to MAX_RETRIES number of times)
        nint remainingUniqueClientIdRetries = 32; // NOTE: it is extremely unlikely that we'd ever generate collisions several times in a row, but this code is here to guard against that extremely unlikely edge case (to prevent a runaway loop)
        while (remainingUniqueClientIdRetries > 0)
        {
            // create our registration record (to save to MongoDB)
            clientId = regionId + "-" + CryptoUtils.GenerateCryptoRandomUrlEncodeSafeString(/*bits: */256);
            var oauthClient = new OAuthClient(clientId)
            {
                ClientIdIssuedAt = clientIdIssuedAt,
                ClientSecrets = clientSecrets,
                RegistrationAccessTokens = null, // NOTE: we initially do not populate this; then we create the registration access token (linking back to this oauth client) and update this record

                // metadata
                RegisteredMetadata = metadata,
            };
            var clientRegistrationRecord = await MongoSerializedOAuthClient.FromAsync(oauthClient);

            // attempt to save the registation record to MongoDB
            // NOTE: we specifically request that we only insert (create) a _new_ record--and not overwrite/upsert an existing one--so that we get an error if there's a client id collision
            try 
            {
                await oauthClientCollection.InsertOneAsync(clientRegistrationRecord);

                // if the operation was successful, break out of our loop
                break;
            }
            catch (MongoWriteException ex) 
            {
                if (ex.WriteError.Category == ServerErrorCategory.DuplicateKey) 
                {
                    // retry, using a different (new) client Id; don't return this error to the caller
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

            remainingUniqueClientIdRetries -= 1;
        }

        // if we were unsuccessful in generating a unique client id, fail now
        if (remainingUniqueClientIdRetries <= 0)
        {
            // we tried generating client ids repeatedly and kept getting collisions; return this error to the caller for diagnostics/debugging
            return MorphicResult.ErrorResult(CreateError.CouldNotCreateUniqueId);
        }

		// NOTE: in the future, we may want to consider registration access tokens that expire; for now, set the expiration to null (i.e. never expires)
        DateTimeOffset? registrationAccessTokenExpiresAt = null;

        // generate a registration access token for our OAuth client
        var registrationAccessTokenOwner = "oauthclient:" + clientId!;
        var createOAuthTokenResult = await OAuthToken.CreateAsync(regionId, OAuthTokenType.RegistrationAccessToken, registrationAccessTokenOwner, registrationAccessTokenExpiresAt);
        if (createOAuthTokenResult.IsError == true) 
        {
            // pass-through the create error
            return MorphicResult.ErrorResult(createOAuthTokenResult.Error!);
        }
        var registrationAccessTokenRecord = createOAuthTokenResult.Value;

        // update our OAuthClient record
        try
        {
            var filter = new BsonDocument { { "_id", clientId! } };
            var encryptedRegistrationAccessTokenId = await CryptoUtils.EncryptPrefixedValueAsync_Throws(AppSecrets.GetOAuthTokenIdCryptoKeyAndIVSecrets, registrationAccessTokenRecord.Id);
            var encryptedRegistrationAccessTokens = new BsonArray { encryptedRegistrationAccessTokenId };
            var update = Builders<MongoSerializedOAuthClient>.Update.Set("encrypted_registration_access_tokens", encryptedRegistrationAccessTokens);
			//
            var updateResult = await oauthClientCollection.UpdateOneAsync(filter, update);
			if (updateResult.IsAcknowledged == false || updateResult.MatchedCount != 1 || updateResult.ModifiedCount != 1) 
			{
				throw new Exception("OAuthClient record created, but could not update the record with registration access tokens");
			}
        }
        catch (Exception ex)
        {
            return MorphicResult.ErrorResult(CreateError.DatabaseFailure(ex));
        }

        // at this point, the supplied metadata (minus any adjustments/filters) is the registered metadata
        var registeredClientMetadata = metadata;

        // return the now-registered client
        var registeredOAuthClient = new MorphicAuthServer.Model.OAuthClient(clientId: clientId!) {
            ClientSecrets = clientSecrets,
            ClientIdIssuedAt = clientIdIssuedAt,
            //
            RegistrationAccessTokens = new List<string>() { registrationAccessTokenRecord.Id },
            //
            RegisteredMetadata = registeredClientMetadata
        };

        return MorphicResult.OkResult(registeredOAuthClient);
    }

    internal record ValidateMetadataError : MorphicAssociatedValueEnum<ValidateMetadataError.Values>
    {
        // enum members
        public enum Values
        {
            InvalidRedirectUri,
            MissingResponseTypeForGrantType,
            UnsupportedGrantType,
            UnsupportedResponseType,
            UnsupportedTokenEndpointAuthMethod,
        }

        // functions to create member instances
        public static ValidateMetadataError InvalidRedirectUri(string redirectUriAsString) => new ValidateMetadataError(Values.InvalidRedirectUri) { RedirectUriAsString = redirectUriAsString };
        public static ValidateMetadataError MissingResponseTypeForGrantType(OAuthResponseType responseType, OAuthGrantType grantType) => new ValidateMetadataError(Values.MissingResponseTypeForGrantType) { ResponseType = responseType, GrantType = grantType };
        public static ValidateMetadataError UnsupportedGrantType(OAuthGrantType grantType) => new ValidateMetadataError(Values.UnsupportedGrantType) { GrantType = grantType };
        public static ValidateMetadataError UnsupportedResponseType(OAuthResponseType responseType) => new ValidateMetadataError(Values.UnsupportedResponseType) { ResponseType = responseType };
        public static ValidateMetadataError UnsupportedTokenEndpointAuthMethod(OAuthTokenEndpointAuthMethod tokenEndpointAuthMethod) => new ValidateMetadataError(Values.UnsupportedTokenEndpointAuthMethod) { TokenEndpointAuthMethod = tokenEndpointAuthMethod };

        // associated values
        public OAuthGrantType? GrantType;
        public string? RedirectUriAsString;
        public OAuthResponseType? ResponseType;
        public OAuthTokenEndpointAuthMethod? TokenEndpointAuthMethod;

        // verbatim required constructor implementation for MorphicAssociatedValueEnums
        private ValidateMetadataError(Values value) : base(value) { }
    }
	//
    // NOTE: this function's job is data integrity protection: it makes sure that whatever metadata is being supplied is both valid and supported by the Morphic Auth Server.
    //       [the web server's HTTP request endpoint functions should also does first-pass filtering, rate limiting, etc.  But this class is more abstract and usable from multiple software packages; it does indeed do some double-checking, but it is not concerned with RFC request/response concerns or rate limiting, etc.
    internal static MorphicResult<MorphicUnit, ValidateMetadataError> ValidateMetadata(OAuthClientMetadata metadata)
    {
        // redirectUris
        if (metadata.RedirectUris is not null)
        {
            foreach (var redirectUriAsString in metadata.RedirectUris)
            {
                // convert redirectUri string to Uri
                Uri? redirectUri;
                var createUriSuccess = Uri.TryCreate(redirectUriAsString, UriKind.Absolute, out redirectUri);
                if (createUriSuccess == false)
                {
                    return MorphicResult.ErrorResult(ValidateMetadataError.InvalidRedirectUri(redirectUriAsString));
                }

                // the URI was parseable; now validate that it complies with our rules for acceptable redirect URIs
                //
                var redirectUriScheme = redirectUri!.Scheme.ToLowerInvariant();
                switch (redirectUriScheme)
                {
                    case "http":
                        // http scheme is allowed, but only for localhost
                        {
                            switch (redirectUri.Host.ToLowerInvariant())
                            {
                                case "localhost":
                                case "127.0.0.1":
                                case "[::1]":
                                    // allowed for http scheme
                                    break;
                                default:
                                    // no other hosts are allowed with the http scheme
                                    return MorphicResult.ErrorResult(ValidateMetadataError.InvalidRedirectUri(redirectUriAsString));
                            }
                        }
                        break;
                    case "https":
                        // https scheme is allowed
                        break;
                    default:
                        // other schemes are not allowed
                        return MorphicResult.ErrorResult(ValidateMetadataError.InvalidRedirectUri(redirectUriAsString));
                }
            }
        }

        // tokenEndpointAuthMethod
        // NOTE: in the future, we may want to consider restricting token endpoint auth methods (e.g. disallowing CLIENT_POST)
        switch (metadata.TokenEndpointAuthMethod)
        {
            case OAuthTokenEndpointAuthMethod.None:
            case OAuthTokenEndpointAuthMethod.ClientSecretBasic:
            case OAuthTokenEndpointAuthMethod.ClientSecretPost:
                // these token endpoint auth methods are supported by this auth server
                break;
            default:
                return MorphicResult.ErrorResult(ValidateMetadataError.UnsupportedTokenEndpointAuthMethod(metadata.TokenEndpointAuthMethod));
        }

        // grantTypes
        foreach (var grantType in metadata.GrantTypes)
        {
            switch (grantType)
            {
                case OAuthGrantType.AuthorizationCode:
                case OAuthGrantType.Password:
                    // these grant types are supported by this auth server
                    break;
                case OAuthGrantType.ClientCredentials:
                case OAuthGrantType.Implicit:
                case OAuthGrantType.JwtBearer:
                case OAuthGrantType.RefreshToken:
                case OAuthGrantType.Saml2Bearer:
                default:
                    return MorphicResult.ErrorResult(ValidateMetadataError.UnsupportedGrantType(grantType));
            }
        }

        // responseTypes
        foreach (var responseType in metadata.ResponseTypes)
        {
            switch (responseType)
            {
                case OAuthResponseType.Code:
                case OAuthResponseType.Token:
                    // these response types are supported by this auth server
                    break;
                default:
                    return MorphicResult.ErrorResult(ValidateMetadataError.UnsupportedResponseType(responseType));
            }
        }

        // enforce the required mapping between certain grantTypes and responseTypes (i.e. make sure that any required response type is present for each grant type)
        foreach (var grantType in metadata.GrantTypes)
        {
            switch (grantType)
            {
                case OAuthGrantType.AuthorizationCode:
                    {
                        if (metadata.ResponseTypes.Contains(OAuthResponseType.Code) == false)
                        {
                            return MorphicResult.ErrorResult(ValidateMetadataError.MissingResponseTypeForGrantType(OAuthResponseType.Code, OAuthGrantType.AuthorizationCode));
                        }
                    }
                    break;
                case OAuthGrantType.Implicit:
                    {
                        if (metadata.ResponseTypes.Contains(OAuthResponseType.Code) == false)
                        {
                            return MorphicResult.ErrorResult(ValidateMetadataError.MissingResponseTypeForGrantType(OAuthResponseType.Token, OAuthGrantType.Implicit));
                        }
                    }
                    break;
                default:
                    break;
            }
        }

        return MorphicResult.OkResult();
    }
}
