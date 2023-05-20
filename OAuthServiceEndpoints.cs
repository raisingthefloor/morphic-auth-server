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
//
// This code is partially derived from the public domain.

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Morphic.Core;
using Morphic.OAuth;
using Morphic.OAuth.Rfc6749;
using Morphic.OAuth.Rfc7591;
using Morphic.Server;
using MorphicAuthServer.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

internal struct OAuthServiceEndpoints {
    /* RFC 7591: OAuth 2.0 Dynamic Registration */
    // client registration endpoint
    internal static async Task RegisterClientAsync(HttpContext context, IConfiguration configuration)
    {
        // verify that the content type is application/json
        var verifyContentTypeHeaderResult = HttpUtils.VerifyContentTypeHeaderIsJson(context);
        if (verifyContentTypeHeaderResult.IsError == true)
        {
            if (verifyContentTypeHeaderResult.Error!.HttpResponse.HasValue == true)
            {
                await HttpUtils.WriteHttpErrorResponseAsync(context, verifyContentTypeHeaderResult.Error.HttpResponse.Value);
            }
            return;
        }

        // verify that the caller accepts a response of content-type application/json
        // NOTE: although the OAuth spec doesn't specify it as a requirement, we require that accept headers specify "application/json"; its use is illustrated in RFC 7591's examples (including in section 3.1);
        //       if this turns out to be overly-restrictive, we could also allow the Accept header to be missing (i.e. let the caller learn the type from the response's Content-Type header)
        var verifyAcceptHeaderResult = HttpUtils.VerifyAcceptHeaderIsJson(context);
        if (verifyAcceptHeaderResult.IsError == true)
        {
            if (verifyAcceptHeaderResult.Error!.HttpResponse.HasValue == true)
            {
                await HttpUtils.WriteHttpErrorResponseAsync(context, verifyAcceptHeaderResult.Error.HttpResponse.Value);
            }
            return;
        }

        // capture the message body
        // NOTE: for memory overflow protection, we limit requests to this endpoint to 256KB; if we need to enlarge this in the future, do so here
        const int MAXIMUM_ALLOWED_REQUEST_SIZE = 256 * 1024;

        var requestBodyAsBytesResult = await HttpUtils.ReadRequestBodyAsByteArrayAsync(context, MAXIMUM_ALLOWED_REQUEST_SIZE);
        if (requestBodyAsBytesResult.IsError == true)
        {
            switch (requestBodyAsBytesResult.Error!.Value)
            {
                case HttpUtils.ReadRequestBodyAsByteArrayError.Values.TooLarge:
                    await HttpUtils.WriteHttpBadRequestErrorResponseAsync(context, "Request body is too large (exceeds " + MAXIMUM_ALLOWED_REQUEST_SIZE.ToString() + " bytes).");
                    return;
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var requestBodyAsBytes = requestBodyAsBytesResult.Value!;

        // NOTE: by specification, the message body should be UTF8-encoded JSON; if we encounter an error trying to decode it then we'll return an HTTP status code indicating the error
        string requestBodyAsJson;
        try
        {
            // convert the body to a JSON string
            requestBodyAsJson = Encoding.UTF8.GetString(requestBodyAsBytes);
        }
        catch
        {
            var httpErrorResponse = new HttpUtils.HttpErrorResponse(
                HttpUtils.HttpResponseCode.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                null,
                string.Empty);
            await HttpUtils.WriteHttpErrorResponseAsync(context, httpErrorResponse);
            return;
        }

        // deserialize the client registration request (body)
        Morphic.OAuth.Rfc7591.Rfc7591ClientRegistrationRequestContent requestContent;
        try
        {
            requestContent = JsonSerializer.Deserialize<Morphic.OAuth.Rfc7591.Rfc7591ClientRegistrationRequestContent>(requestBodyAsJson);
        }
        catch (JsonException)
        {
            await HttpUtils.WriteHttpBadRequestErrorResponseAsync(context, "Request body is invalid JSON.");
            return;
        }

        // parse and validate the client registration request
        var parseClientMetadata = ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContent(requestContent);
        if (parseClientMetadata.IsError == true)
        {
            switch (parseClientMetadata.Error!.Value)
            {
                case ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContentError.Values.GrantTypeAndTokenEndpointAuthMethodAreIncompatible:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidClientMetadata.ToStringValue()!,
                            error_description = "The grant type \"" + parseClientMetadata.Error!.GrantTypeAsString + "\" is incompatible with token endpoint auth method \"" + parseClientMetadata.Error!.TokenEndpointAuthMethodAsString + "\"."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
                case ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContentError.Values.GrantTypeRequiresMissingResponseType:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidClientMetadata.ToStringValue()!,
                            error_description = "The grant type \"" + parseClientMetadata.Error!.GrantTypeAsString + "\" must be registered along with the response type \"" + parseClientMetadata.Error!.ResponseTypeAsString + "\"."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
                case ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContentError.Values.GrantTypeRequiresRedirectUris: 
                    {
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidClientMetadata.ToStringValue()!,
                            error_description = "The grant type \"" + parseClientMetadata.Error!.GrantTypeAsString + "\" requires the registration of at least one redirect uri."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
                case ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContentError.Values.InvalidRedirectUri:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidRedirectUri.ToStringValue()!,
                            error_description = "The redirection URI \"" + parseClientMetadata.Error!.RedirectUriAsString + "\" is not allowed by this server."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
                case ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContentError.Values.UnknownGrantType:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidClientMetadata.ToStringValue()!,
                            error_description = "Grant type \"" + parseClientMetadata.Error!.GrantTypeAsString + "\" is not allowed by this server."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
                case ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContentError.Values.UnknownResponseType:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidClientMetadata.ToStringValue()!,
                            error_description = "Response type \"" + parseClientMetadata.Error!.ResponseTypeAsString + "\" is not allowed by this server."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
                case ClientRegistrationUtils.ParseAndValidateClientRegistrationRequestContentError.Values.UnknownTokenEndpointAuthMethod:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidClientMetadata.ToStringValue()!,
                            error_description = "Token endpoint auth method \"" + parseClientMetadata.Error!.TokenEndpointAuthMethodAsString + "\" is not allowed by this server."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var requestedClientMetadata = parseClientMetadata.Value!;

        // now, reject any client registration options which we don't support
        // NOTE: we have already validated the client registration request, so we cannot filter out any data at this point (unless we refactor out the validation logic, re-call that logic after our filtering is complete, and return appropriate errors to the caller if our filtering caused any validation errors)

        // reject disallowed grant types
        foreach (var grantType in requestedClientMetadata.GrantTypes) {
            switch (grantType) {
                case OAuthGrantType.AuthorizationCode:
                case OAuthGrantType.Password:
                case OAuthGrantType.RefreshToken:
                    // allowed
                    break;
                case OAuthGrantType.Implicit:
                case OAuthGrantType.ClientCredentials:
                case OAuthGrantType.JwtBearer:
                case OAuthGrantType.Saml2Bearer:
                default:
                    {
                        // not allowed in the current implementation
                        var clientRegistrationErrorResponseContent = new Rfc7591ClientRegistrationErrorResponseContent()
                        {
                            error = Rfc7591ClientRegistrationErrorCodes.InvalidClientMetadata.ToStringValue()!,
                            error_description = "The grant type \"" + grantType.ToStringValue()! + "\" is not supported for dynamic client registration on this server."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
            }
        }

        // validate the caller's initial access token
        // NOTE: while OAuth does not require IATs, our current implementation does; in the future, we may loosen this restriction a bit by only requiring IATs for certain client registrations
        var nullableBearerToken = HttpUtils.ExtractBearerTokenFromAuthorizationHeaderValue(context);
        if (nullableBearerToken is null) 
        {
            // let the caller know that they're unauthorized, and that they need to provide a bearer (initial access) token
            HttpUtils.SetHttpResponseStatusToUnauthorized(context);
            await context.Response.WriteAsync(String.Empty);
            return;
        }
        var bearerToken = nullableBearerToken!;
        //
        var loadedInitialAccessToken = await MorphicAuthServer.Model.OAuthToken.LoadAsync(bearerToken);
        if (loadedInitialAccessToken.IsError == true)
        {
            switch (loadedInitialAccessToken.Error!.Value) 
            {
                case MorphicAuthServer.Model.LoadError.Values.NotFound:
                    {
                        // let the caller know that their bearer token was denied
                        HttpUtils.SetHttpResponseStatusToForbidden(context);
                        await context.Response.WriteAsync(String.Empty);
                        return;
                    }
                case MorphicAuthServer.Model.LoadError.Values.DatabaseFailure:
                default:
                    {
                        // let the caller know that we experienced an internal server error
                        await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                        return;
                    }
            }
        }
        //
        // NOTE: in our current implementation, we do not test initial access tokens for anything beyond just their existence; in the future, if we want to limit IATs to certain client IDs, etc. In that case, We would apply that logic here.

        // NOTE: in the current implementation, we register the client metadata as requested
        var registeredClientMetadata = requestedClientMetadata;

        // capture our region id; we'll need this to create our client id
        var regionId = MorphicAuthServer.AppSettings.GetRegionId();
        if (regionId is null || regionId.Length < 1)
        {
            await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
            return;
        };
        // verify that the region id can be parsed as an unsigned number
        if (UInt32.TryParse(regionId, out var regionIdAsUInt32) == false) {
            await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
            return;
        }

        // the request has passed validation; register the client
        var createOAuthClientResult = await MorphicAuthServer.Model.OAuthClient.CreateAsync(registeredClientMetadata, regionId);
        if (createOAuthClientResult.IsError == true)
        {
            switch (createOAuthClientResult.Error!.Value)
            {
                case MorphicAuthServer.Model.CreateError.Values.CouldNotCreateUniqueId:
                    // it is extremely unlikely that attempting to create a unique ID would fail, but just in case it does we capture the error
                    System.Console.WriteLine("ERROR: could not create unique ID");
                    //
                    // let the caller know that we experienced an internal server error
                    await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                    return;
                case MorphicAuthServer.Model.CreateError.Values.CryptographyFailed:
                    // cryptography should never fail
                    System.Console.WriteLine("ERROR: cryptography failed");
                    //
                    // let the caller know that we experienced an internal server error
                    await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                    return;
                case MorphicAuthServer.Model.CreateError.Values.DatabaseFailure:
                    var exception = createOAuthClientResult.Error!.Exception!;
                    System.Console.WriteLine("ERROR: database failure; ex: " + exception.ToString());
                    //
                    // let the caller know that we experienced an internal server error
                    await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                    return;
                case MorphicAuthServer.Model.CreateError.Values.ValidationFailed:
                    // we have already validated the request, so this error should never occur
                    //
                    // let the caller know that we experienced an internal server error
                    await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                    return;
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var registeredOAuthClient = createOAuthClientResult.Value!;

        // convert our client record's registered grant and response types into string arrays
        List<string>? grantTypesAsStringArray = new List<string>();
        foreach (var grantType in registeredOAuthClient.RegisteredMetadata.GrantTypes)
        {
            grantTypesAsStringArray.Add(grantType.ToStringValue()!);
        }
        if (grantTypesAsStringArray.Count == 0) { grantTypesAsStringArray = null; }
        //
        List<string>? responseTypesAsStringArray = new List<string>();
        foreach (var responseType in registeredOAuthClient.RegisteredMetadata.ResponseTypes)
        {
            responseTypesAsStringArray.Add(responseType.ToStringValue()!);
        }
        if (responseTypesAsStringArray.Count == 0) { responseTypesAsStringArray = null; }

        var registrationClientUriBase = "https://auth.morphic.org/oauth/register/";

        // calculate the registered oauth client's "SecretExpiresAt" value to return to the caller (based on whether a secret was set or not, and whether it expires or not)
        string? registeredOAuthClientSecret;
        ulong? registeredOAuthClientSecretExpiresAt;
        if (registeredOAuthClient.ClientSecrets is not null)
        {
            if (registeredOAuthClient.ClientSecrets?.Count != 1) 
            {
                throw new Exception("Programming error: new OAuthClients should only have one client secret");
            }
            var initialClientSecret = registeredOAuthClient.ClientSecrets[0];
            registeredOAuthClientSecret = initialClientSecret.HashedValue.CleartextValue!;

            // NOTE: if clientSecret was issued, this field is mandatory (non-nullable); it may be set as zero (0) to designate 'no expiration'
            if (initialClientSecret.ExpiresAt is not null) {
                registeredOAuthClientSecretExpiresAt = (ulong)(initialClientSecret.ExpiresAt.Value).ToUnixTimeSeconds();
            }
            else
            {
                registeredOAuthClientSecretExpiresAt = 0;
            }
        }
        else 
        {
            registeredOAuthClientSecret = null;
            registeredOAuthClientSecretExpiresAt = null;
        }

        var clientInformationResponseContent = new Morphic.OAuth.Rfc7591.Rfc7591ClientInformationResponseContent()
        {
            registration_access_token = registeredOAuthClient.RegistrationAccessTokens?.Count > 0 ? registeredOAuthClient.RegistrationAccessTokens![0] : null,
            registration_client_uri = registeredOAuthClient.RegistrationAccessTokens?.Count > 0 ? registrationClientUriBase + registeredOAuthClient.ClientId : null,
            //
            client_id = registeredOAuthClient.ClientId,
            client_id_issued_at = registeredOAuthClient.ClientIdIssuedAt != null ? (ulong)((DateTimeOffset)registeredOAuthClient.ClientIdIssuedAt.Value).ToUnixTimeSeconds() : null,
            client_secret = registeredOAuthClientSecret,
            client_secret_expires_at = registeredOAuthClientSecretExpiresAt,
            //
            redirect_uris = registeredOAuthClient.RegisteredMetadata.RedirectUris,
            token_endpoint_auth_method = registeredOAuthClient.RegisteredMetadata.TokenEndpointAuthMethod.ToStringValue(),
            grant_types = grantTypesAsStringArray,
            response_types = responseTypesAsStringArray,
            software_id = registeredOAuthClient.RegisteredMetadata.SoftwareId,
            software_version = registeredOAuthClient.RegisteredMetadata.SoftwareVersion,
        };

        // return the client information response to the caller
        context.Response.StatusCode = (int)HttpUtils.HttpResponseCode.HTTP_201_CREATED;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-store";
        //
        var responseBodyContent = JsonSerializer.Serialize(clientInformationResponseContent);
        await context.Response.WriteAsync(responseBodyContent);
	}

	// NOTES on FUTURE endpoints:
	// 1. client id registration get/update endpoint: if a caller calls this endpoint using their valid registration access token, we'd purge the oldest secret and any expired secrets, create a new secret and return the new secret
	// 											      also, whenever a caller updated the registration endpoint, we'd delete all registration access tokens other than the one used for the update
	//                                                [re-evaluate this mechanism when we create it; essentially we want to make sure that users can never get "locked out" of their client id's registration endpoint and can also get a new client secret]

    /* RFC 6749: The OAuth 2.0 Authorization Framework */
    // token endpoint
    internal static async Task ObtainAccessTokenAsync(HttpContext context, IConfiguration configuration)
    {
        // verify that the content type is "application/x-www-form-urlencoded"
        var verifyContentTypeHeaderResult = HttpUtils.VerifyContentTypeHeaderIsWwwFormUrlEncodedAsync(context);
        if (verifyContentTypeHeaderResult.IsError == true)
        {
            if (verifyContentTypeHeaderResult.Error!.HttpResponse.HasValue == true)
            {
                await HttpUtils.WriteHttpErrorResponseAsync(context, verifyContentTypeHeaderResult.Error.HttpResponse.Value);
            }
            return;
        }

        // if the caller supplied the "Accept" header, verify that the caller accepts a response of content-type "application/json"
        if (HttpUtils.AcceptHeaderIsPresent(context) == true) {
            var verifyAcceptHeaderResult = HttpUtils.VerifyAcceptHeaderIsJson(context);
            if (verifyAcceptHeaderResult.IsError == true)
            {
                if (verifyAcceptHeaderResult.Error!.HttpResponse.HasValue == true)
                {
                    await HttpUtils.WriteHttpErrorResponseAsync(context, verifyAcceptHeaderResult.Error.HttpResponse.Value);
                }
                return;
            }
        }

        // capture the caller's authorization header (client id and password)
        var authorizationHeader = context.Request.Headers.Authorization;
        var extractUsernameAndPasswordResult = HttpUtils.ExtractUsernameAndPasswordFromBasicAuthorizationHeaderValue(context);
        if (extractUsernameAndPasswordResult.IsError == true) 
        {
            switch (extractUsernameAndPasswordResult.Error!.Value) 
            {
                case HttpUtils.ExtractUsernameAndPasswordError.Values.AuthorizationSchemeMustBeBasic:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
                        {
                            error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                            error_description = "The requested authorization scheme is not supported."
                        };
                        await HttpUtils.WriteHttpUnauthorizedJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent), "Bearer");
                        return;
                    }
                case HttpUtils.ExtractUsernameAndPasswordError.Values.BasicAuthorizationValueIsNotBase64Encoded:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
                        {
                            error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                            error_description = "The authorization header is malformed."
                        };
                        await HttpUtils.WriteHttpUnauthorizedJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent), "Bearer");
                        return;
                    }
                case HttpUtils.ExtractUsernameAndPasswordError.Values.MultipleAuthorizationHeadersAreNotAllowed:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
                        {
                            error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                            error_description = "Multiple authorization headers are not allowed."
                        };
                        await HttpUtils.WriteHttpUnauthorizedJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent), "Bearer");
                        return;
                    }
                case HttpUtils.ExtractUsernameAndPasswordError.Values.NoAuthorizationHeader:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
                        {
                            error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                            error_description = "This authentication method is not supported for this client."
                        };
                        await HttpUtils.WriteHttpUnauthorizedJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent), "Bearer");
                        return;
                    }
                case HttpUtils.ExtractUsernameAndPasswordError.Values.UsernameAndPasswordAreMalformed:
                    {
                        var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
                        {
                            error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                            error_description = "The client id and/or client password are malformed."
                        };
                        await HttpUtils.WriteHttpUnauthorizedJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent), "Bearer");
                        return;
                    }
                default:
                    throw new MorphicUnhandledErrorException();
            }
        }
        var clientId = extractUsernameAndPasswordResult.Value!.Username;
        var clientSecret = extractUsernameAndPasswordResult.Value!.Password;

        // NOTE: by specification, the message body must be x-www-form-urlencoded; if we encounter an error trying to decode it then we'll return an HTTP status code indicating the error
        // NOTE: instead of manually retrieving the body contents, we'll use Request.Form to extract the application/x-www-form-urlencoded body contents
        //
        // grant_type
        string nullableGrantTypeAsString = context.Request.Form["grant_type"];
        if (nullableGrantTypeAsString is null) {
            var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
            {
                error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidRequest.ToStringValue()!,
                error_description = "The grant_type is missing."
            };
            await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
            return;
        }
        var grantTypeAsString = nullableGrantTypeAsString!;
        //
        OAuthGrantType? nullableGrantType = MorphicEnum<OAuthGrantType>.FromStringValue(grantTypeAsString);
        if (nullableGrantType is null) {
            var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
            {
                error = Rfc6749AccessTokenErrorResponseErrorCodes.UnsupportedGrantType.ToStringValue()!,
                error_description = "The grant_type is malformed or unsupported."
            };
            await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
            return;
        }
        var grantType = nullableGrantType!.Value;
        //
        // username (required for one or more grant types)
        string? nullableUsername = context.Request.Form["username"];
        if (nullableUsername is null)
        {
            var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
            {
                error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidRequest.ToStringValue()!,
                error_description = "The username is missing."
            };
            await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
            return;
        }
        string username = nullableUsername!;
        //
        // password (required for one or more grant types)
        string? nullablePassword = context.Request.Form["password"];
        if (nullablePassword is null)
        {
            var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
            {
                error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidRequest.ToStringValue()!,
                error_description = "The password is missing."
            };
            await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
            return;
        }
        string password = nullablePassword!;
        //
        // scope (optional)
        string? scope = context.Request.Form["scope"];

        // attempt to load the client
		// NOTE: in the current implementation, a client ID must always be provided
        var loadClientResult = await MorphicAuthServer.Model.OAuthClient.LoadAsync(clientId);
        if (loadClientResult.IsError == true) 
        {
            switch (loadClientResult.Error!.Value)
            {
                case MorphicAuthServer.Model.LoadError.Values.NotFound:
                    {
                        // NOTE: to prevent leaking of client ids, we return a generic error if either the client id or the client secret are invalid
                        var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
                        {
                            error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                            error_description = "The client_id and/or client_secret are incorrect."
                        };
                        await HttpUtils.WriteHttpUnauthorizedJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent), "Bearer");
                        return;
                    }
                case MorphicAuthServer.Model.LoadError.Values.DatabaseFailure:
                default:
                    {
                        // let the caller know that we experienced an internal server error
                        await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                        return;
                    }
            }
        }
        var client = loadClientResult.Value!;
        
        // validate that the client password is correct (and, if it has an expiration date, that it is not expired)
        // NOTE: we verify the client secret after reading and validating the message body as a security best-practice (i.e. we return errors about the content before returning errors about authentication)
        bool clientSecretMatchesAndIsNotExpired = false;
        if (client.ClientSecrets is not null) 
        {
            foreach (var secret in client.ClientSecrets)
            {
                var clientSecretMatches = secret.HashedValue.ConfirmPasswordMatch(clientSecret);    
                if (clientSecretMatches == true)
                {
                    // verify that the client secret has not expired
                    if ((secret.ExpiresAt is null) || (DateTimeOffset.UtcNow < secret.ExpiresAt!.Value)) 
                    {
                        clientSecretMatchesAndIsNotExpired = true;
                        break;
                    }
                }
            }
        }
        //
        if (clientSecretMatchesAndIsNotExpired == false)
        {
            // NOTE: to prevent leaking of client ids, we return a generic error if either the client id or the client secret are invalid
            var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
            {
                error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                error_description = "The client_id and/or client_secret are incorrect."
            };
            await HttpUtils.WriteHttpUnauthorizedJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent), "Bearer");
            return;
        }

        // verify that the client can use the token endpoint auth method
        // NOTE: we verify that the client can use the token endpoint auth method after authenticating the client as a security best-practice (i.e. to prevent leakage of client ids).
        if (client.RegisteredMetadata.TokenEndpointAuthMethod != OAuthTokenEndpointAuthMethod.ClientSecretBasic)
        {
            var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
            {
                error = Rfc6749AccessTokenErrorResponseErrorCodes.InvalidClient.ToStringValue()!,
                error_description = "This authentication method is not supported for this client."
            };
            await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
            return;
        }

        // verify that the client is registered to use this grant type
        // NOTE: we verify that the client can use the specified grant type after authenticating the client as a security best-practice (i.e. to prevent leakage of client ids).
        if (client.RegisteredMetadata.GrantTypes.Contains(grantType) == false)
        {
            var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
            {
                error = Rfc6749AccessTokenErrorResponseErrorCodes.UnauthorizedClient.ToStringValue()!,
                error_description = "The client is not authorized for the requested grant_type."
            };
            await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
            return;
        }

        // capture our region id; we'll need this to create an access token
        var regionId = MorphicAuthServer.AppSettings.GetRegionId();
        if (regionId is null || regionId.Length < 1)
        {
            await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
            return;
        };
        // verify that the region id can be parsed as an unsigned number
        if (UInt32.TryParse(regionId, out var regionIdAsUInt32) == false) {
            await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
            return;
        }

        // process the remaining components of the request based on the grant type and then issue a token; if the grant type is not supported by this implementation, return an appropriate error
        switch (grantType)
        {
            case OAuthGrantType.Password:
                {
                    // NOTE: in our current implementation, we use the user's email address as the user's username
                    var userEmailAddress = new MorphicAuthServer.Model.UserEmailAddress(username);

                    // attempt to load the user
                    var loadUserResult = await MorphicAuthServer.Model.User.LoadAsync(userEmailAddress);
                    if (loadUserResult.IsError == true) 
                    {
                        switch (loadUserResult.Error!.Value)
                        {
                            case MorphicAuthServer.Model.LoadError.Values.NotFound:
                                {
                                    // NOTE: to prevent leaking of usernames or other personally-identifiable information, we return a generic error if either the username or the user's password are invalid
                                    var errorResponseString = "The username and/or password are incorrect.";
                                    await HttpUtils.WriteHttpUnauthorizedErrorResponseAsync(context, errorResponseString);
                                    return;
                                }
                            case MorphicAuthServer.Model.LoadError.Values.DatabaseFailure:
                            default:
                                {
                                    // let the caller know that we experienced an internal server error
                                    await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                                    return;
                                }
                        }
                    }
                    var user = loadUserResult.Value!;

                    // load the user's credentials (and then find the password credential so that we can match the provided password against their stored password)
                    var loadAllUserCredentialsResult = await MorphicAuthServer.Model.UserCredential.LoadAllForUserAsync(user.Id);
                    if (loadAllUserCredentialsResult.IsError == true) {
                        switch (loadUserResult.Error!.Value)
                        {
                            case MorphicAuthServer.Model.LoadError.Values.NotFound:
                                {
                                    // NOTE: to prevent leaking of usernames or other personally-identifiable information, we return a generic error if either the username or the user's password are invalid
                                    var errorResponseString = "The username and/or password are incorrect.";
                                    await HttpUtils.WriteHttpUnauthorizedErrorResponseAsync(context, errorResponseString);
                                    return;
                                }
                            case MorphicAuthServer.Model.LoadError.Values.DatabaseFailure:
                            default:
                                {
                                    // let the caller know that we experienced an internal server error
                                    await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                                    return;
                                }
                        }
                    }
                    var allUserCredentials = loadAllUserCredentialsResult.Value!;
                    //
                    var userPasswordCredentials = allUserCredentials.Where(x => x.Type == "password");
					// NOTE: a user is only allowed to have up to 1 password credential; if we cannot find a password credential or if somehow the user has multiple credentials, fail the auth attempt
                    if (userPasswordCredentials.Count() != 1) 
                    {
						if (userPasswordCredentials.Count() > 1)
						{
							// NOTE: we might want to consider sending a log event to devops if the userPasswordCredentials.Count() were ever greater than 1, as it would indicate a system/code error
                        	System.Console.WriteLine("ERROR: User has multiple 'password' credentials; this is not allowed and represents a data integrity issue for the user in the database");
						}
                        // NOTE: to prevent leaking of usernames or other personally-identifiable information, we return a generic error if either the username or the user's password are invalid
                        var errorResponseString = "The username and/or password are incorrect.";
                        await HttpUtils.WriteHttpUnauthorizedErrorResponseAsync(context, errorResponseString);
                        return;
                    }
                    var userPasswordCredential = userPasswordCredentials.First();

                    // verify the user's password
                    var userPasswordCredentialData = (MorphicAuthServer.Model.UserCredentialDataObjects.PasswordUserCredentialData)userPasswordCredential.Data;
                    var userPasswordMatches = userPasswordCredentialData.HashedPassword.ConfirmPasswordMatch(password);

                    if (userPasswordMatches == false) 
                    {
                        // NOTE: to prevent leaking of usernames or other personally-identifiable information, we return a generic error if either the username or the user's password are invalid
                        var errorResponseString = "The username and/or password are incorrect.";
                        await HttpUtils.WriteHttpUnauthorizedErrorResponseAsync(context, errorResponseString);
                        return;
                    }

                    // NOTE: in the current implementation, OAuth tokens expire after 60 days
                    DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddDays(60);

                    // NOTE: if we add refresh token support in the future, we should use a default of one year (365/366 days); this will allow clients to remain authenticated as long as they refresh their tokens once a year (i.e. are used at least once during the last ~10 months of that year period)

                    // NOTE: we create a reverse lookup for every access token (so that we can search for all tokens owned by a specific user, can clean up tokens when a user is deleted, etc.)
                    var accessTokenOwner = "user:" + user.Id;

                    // the client and user credentials have both passed validation; issue the token
                    var createOAuthTokenResult = await MorphicAuthServer.Model.OAuthToken.CreateAsync(regionId, MorphicAuthServer.Model.OAuthTokenType.AccessToken, accessTokenOwner, expiresAt);
                    if (createOAuthTokenResult.IsError == true) 
                    {
                        switch (createOAuthTokenResult.Error!.Value)
                        {
                            case MorphicAuthServer.Model.CreateError.Values.CouldNotCreateUniqueId:
                                // it is extremely unlikely that attempting to create a unique ID would fail, but just in case it does we capture the error
                                System.Console.WriteLine("ERROR: could not create unique ID in ObtainAccessTokenAsync(...)");
                                //
                                // let the caller know that we experienced an internal server error
                                await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                                return;
                            case MorphicAuthServer.Model.CreateError.Values.CryptographyFailed:
                                // cryptography should never fail
                                System.Console.WriteLine("ERROR: cryptography failed in ObtainAccessTokenAsync(...)");
                                //
                                // let the caller know that we experienced an internal server error
                                await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                                return;
                            case MorphicAuthServer.Model.CreateError.Values.DatabaseFailure:
                                var exception = createOAuthTokenResult.Error!.Exception!;
                                System.Console.WriteLine("ERROR: database failure in ObtainAccessTokenAsync(...); ex: " + exception.ToString());
                                //
                                // let the caller know that we experienced an internal server error
                                await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                                return;
                            case MorphicAuthServer.Model.CreateError.Values.ValidationFailed:
                                // we have already validated the request, so this error should never occur
                                System.Console.WriteLine("ERROR: validation failure in ObtainAccessTokenAsync(...)");
                                //
                                // let the caller know that we experienced an internal server error
                                await HttpUtils.WriteHttpErrorResponseAsync(context, HttpUtils.HttpErrorResponse.InternalServerErrorResponse);
                                return;
                            default:
                                throw new MorphicUnhandledErrorException();
                        }
                    }
                    var oauthToken = createOAuthTokenResult.Value!;

                    long? oauthTokenExpiresIn = null;
                    if (oauthToken.ExpiresAt is not null) {
                        oauthTokenExpiresIn = Math.Max(oauthToken.ExpiresAt!.Value.ToUnixTimeSeconds() - DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 0);
                    }

                    var accessTokenResponseContent = new Morphic.OAuth.Rfc6749.Rfc6749AccessTokenSuccessfulResponseContent()
                    {
                        access_token = oauthToken.Id,
                        token_type = "bearer",
                        expires_in = oauthTokenExpiresIn,
                        refresh_token = null, // not supported in the current implementation
                        scope = null,         // not supported in the current implementation
                    };

                    // return the access token response to the caller
                    context.Response.StatusCode = (int)HttpUtils.HttpResponseCode.HTTP_200_OK;
                    context.Response.ContentType = "application/json";
                    context.Response.Headers.CacheControl = "no-store";
                    context.Response.Headers.Pragma = "no-store";
                    //
                    var responseBodyContent = JsonSerializer.Serialize(accessTokenResponseContent);
                    await context.Response.WriteAsync(responseBodyContent); 
                }
                break;
            default:
                {
                    var clientRegistrationErrorResponseContent = new Rfc6749AccessTokenErrorResponseContent()
                    {
                        error = Rfc6749AccessTokenErrorResponseErrorCodes.UnsupportedGrantType.ToStringValue()!,
                        error_description = "The grant type \"" + grantTypeAsString + "\" is unsupported."
                    };
                    await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                    return;
                }
        }
	}
}