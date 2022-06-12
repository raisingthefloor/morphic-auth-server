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
using Morphic.Core;
using Morphic.OAuth;
using System.Collections.Generic;

public struct OAuthClientMetadata
{
    [BsonElement("redirect_uris"), BsonIgnoreIfNull]
    public List<string>? RedirectUris;
    //
    [BsonElement("token_endpoint_auth_method")]
    public OAuthTokenEndpointAuthMethod TokenEndpointAuthMethod { get; set; }
    //
    [BsonElement("grant_types")]
    public List<OAuthGrantType> GrantTypes { get; set; }
    //
    [BsonElement("response_types")]
    public List<OAuthResponseType> ResponseTypes { get; set; }
    //
    [BsonElement("software_id"), BsonIgnoreIfNull]
    public string? SoftwareId { get; set; }
    //
    [BsonElement("software_version"), BsonIgnoreIfNull]
    public string? SoftwareVersion { get; set; }

    internal static MorphicResult<OAuthClientMetadata, MorphicUnit> TryFrom(MongoSerializedOAuthClientMetadata mongoRecord)
    {
        var redirectUris = mongoRecord.RedirectUris;
        //
        var tokenEndpointAuthMethod = MorphicEnum<OAuthTokenEndpointAuthMethod>.FromStringValue(mongoRecord.TokenEndpointAuthMethod);
        if (tokenEndpointAuthMethod is null) { return MorphicResult.ErrorResult(); }
        //
        List<OAuthGrantType> grantTypes = new();
        foreach (var grantTypeAsString in mongoRecord.GrantTypes) 
        {
            var grantType = MorphicEnum<OAuthGrantType>.FromStringValue(grantTypeAsString);
            if (grantType is null) { return MorphicResult.ErrorResult(); }
            grantTypes.Add(grantType.Value);
        }
        //
        List<OAuthResponseType> responseTypes = new();
        foreach (var responseTypeAsString in mongoRecord.ResponseTypes) 
        {
            var responseType = MorphicEnum<OAuthResponseType>.FromStringValue(responseTypeAsString);
            if (responseType is null) { return MorphicResult.ErrorResult(); }
            responseTypes.Add(responseType.Value);
        }
        //
        var softwareId = mongoRecord.SoftwareId;
        //
        var softwareVersion = mongoRecord.SoftwareVersion;

        var result = new OAuthClientMetadata() {
            RedirectUris = redirectUris,
            TokenEndpointAuthMethod = tokenEndpointAuthMethod.Value,
            GrantTypes = grantTypes,
            ResponseTypes = responseTypes,
            SoftwareId = softwareId,
            SoftwareVersion = softwareVersion
        };
        return MorphicResult.OkResult(result);
    }
}

internal struct MongoSerializedOAuthClientMetadata 
{
    [BsonElement("redirect_uris"), BsonIgnoreIfNull]
    public List<string>? RedirectUris;
    //
    [BsonElement("token_endpoint_auth_method")]
    public string TokenEndpointAuthMethod { get; set; }
    //
    [BsonElement("grant_types")]
    public List<string> GrantTypes { get; set; }
    //
    [BsonElement("response_types")]
    public List<string> ResponseTypes { get; set; }
    //
    [BsonElement("software_id"), BsonIgnoreIfNull]
    public string? SoftwareId { get; set; }
    //
    [BsonElement("software_version"), BsonIgnoreIfNull]
    public string? SoftwareVersion { get; set; }

    internal static MongoSerializedOAuthClientMetadata From(OAuthClientMetadata metadata)
    {
        var redirectUris = metadata.RedirectUris;
        //
        var tokenEndpointAuthMethod = metadata.TokenEndpointAuthMethod.ToStringValue()!;
        //
        List<string> grantTypes = new();
        foreach (var metadataGrantType in metadata.GrantTypes) 
        {
            grantTypes.Add(metadataGrantType.ToStringValue()!);
        }
        //
        List<string> responseTypes = new();
        foreach (var metadataResponseType in metadata.ResponseTypes) 
        {
            responseTypes.Add(metadataResponseType.ToStringValue()!);
        }
        //
        var softwareId = metadata.SoftwareId;
        //
        var softwareVersion = metadata.SoftwareVersion;

        var result = new MongoSerializedOAuthClientMetadata() {
            RedirectUris = redirectUris,
            TokenEndpointAuthMethod = tokenEndpointAuthMethod,
            GrantTypes = grantTypes,
            ResponseTypes = responseTypes,
            SoftwareId = softwareId,
            SoftwareVersion = softwareVersion
        };
        return result;
    }
}