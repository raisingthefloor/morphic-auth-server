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
        // NOTE: we have already validated the client registration request, so we cannot filter out any data at this point (unless we refactor out the validation logic and then re-call it after our filtering is complete...and return appropriate errors if our filtering caused any validation errors)

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
                            error_description = "The grant type \"" + grantType + "\" is not supported for dynamic client registration on this server."
                        };
                        await HttpUtils.WriteHttpBadRequestJsonErrorResponseAsync(context, JsonSerializer.Serialize(clientRegistrationErrorResponseContent));
                        return;
                    }
            }
        }

	}

    // token endpoint
    // internal static async Task GetTokenAsync(HttpContext context, string tokenId)
    // {
    //     // await context.Response.WriteAsync("Token: " + tokenId);
    //     throw new NotImplementedException();
    // }
}