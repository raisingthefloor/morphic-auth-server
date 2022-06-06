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

using Morphic.Core;
using Morphic.OAuth;
using MorphicAuthServer.Model;
using System;
using System.Collections.Generic;

namespace MorphicAuthServer.Utils
{
    internal struct ClientRegistrationUtils
    {
        public record ParseAndValidateClientRegistrationRequestContentError : MorphicAssociatedValueEnum<ParseAndValidateClientRegistrationRequestContentError.Values>
        {
            // enum members
            public enum Values
            {
                GrantTypeAndTokenEndpointAuthMethodAreIncompatible,
                GrantTypeRequiresMissingResponseType,
                GrantTypeRequiresRedirectUris,
                InvalidRedirectUri,
                UnknownGrantType,
                UnknownResponseType,
                UnknownTokenEndpointAuthMethod,
            }

            // functions to create member instances
            public static ParseAndValidateClientRegistrationRequestContentError GrantTypeAndTokenEndpointAuthMethodAreIncompatible(string grantTypeAsString, string tokenEndpointAuthMethodAsString) => new ParseAndValidateClientRegistrationRequestContentError(Values.GrantTypeAndTokenEndpointAuthMethodAreIncompatible) { GrantTypeAsString = grantTypeAsString, TokenEndpointAuthMethodAsString = tokenEndpointAuthMethodAsString };
            public static ParseAndValidateClientRegistrationRequestContentError GrantTypeRequiresMissingResponseType(string grantTypeAsString, string responseTypeAsString) => new ParseAndValidateClientRegistrationRequestContentError(Values.GrantTypeRequiresMissingResponseType) { GrantTypeAsString = grantTypeAsString, ResponseTypeAsString = responseTypeAsString };
            public static ParseAndValidateClientRegistrationRequestContentError GrantTypeRequiresRedirectUris(string grantTypeAsString) => new ParseAndValidateClientRegistrationRequestContentError(Values.GrantTypeRequiresRedirectUris) { GrantTypeAsString = grantTypeAsString };
            public static ParseAndValidateClientRegistrationRequestContentError InvalidRedirectUri(string redirectUriAsString) => new ParseAndValidateClientRegistrationRequestContentError(Values.InvalidRedirectUri) { RedirectUriAsString = redirectUriAsString };
            public static ParseAndValidateClientRegistrationRequestContentError UnknownGrantType(string grantTypeAsString) => new ParseAndValidateClientRegistrationRequestContentError(Values.UnknownGrantType) { GrantTypeAsString = grantTypeAsString };
            public static ParseAndValidateClientRegistrationRequestContentError UnknownResponseType(string responseTypeAsString) => new ParseAndValidateClientRegistrationRequestContentError(Values.UnknownResponseType) { ResponseTypeAsString = responseTypeAsString };
            public static ParseAndValidateClientRegistrationRequestContentError UnknownTokenEndpointAuthMethod(string tokenEndpointAuthMethodAsString) => new ParseAndValidateClientRegistrationRequestContentError(Values.UnknownTokenEndpointAuthMethod) { TokenEndpointAuthMethodAsString = tokenEndpointAuthMethodAsString };

            // associated values
            public string? GrantTypeAsString;
            public string? RedirectUriAsString;
            public string? ResponseTypeAsString;
            public string? TokenEndpointAuthMethodAsString;

            // verbatim required constructor implementation for MorphicAssociatedValueEnums
            private ParseAndValidateClientRegistrationRequestContentError(Values value) : base(value) { }
        }
        //
        internal static MorphicResult<OAuthClientMetadata, ParseAndValidateClientRegistrationRequestContentError> ParseAndValidateClientRegistrationRequestContent(Morphic.OAuth.Rfc7591.Rfc7591ClientRegistrationRequestContent request)
        {
            // capture the token endpoint auth method
            //
            // redirect_uris
            var redirectUrisAsStrings = request.redirect_uris;
            //
            // token_endpoint_auth_method
            OAuthTokenEndpointAuthMethod tokenEndpointAuthMethod;
            var tokenEndpointAuthMethodAsString = request.token_endpoint_auth_method;
            if (tokenEndpointAuthMethodAsString is not null)
            {
                var nullableTokenEndpointAuthMethod = MorphicEnum<OAuthTokenEndpointAuthMethod>.FromStringValue(tokenEndpointAuthMethodAsString);
                if (nullableTokenEndpointAuthMethod is null)
                {
                    return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.UnknownTokenEndpointAuthMethod(tokenEndpointAuthMethodAsString));
                }
                tokenEndpointAuthMethod = nullableTokenEndpointAuthMethod.Value;
            }
            else
            {
                // if no token endpoint auth method was provided, use the default
                // RFC 7591 Sec. 2: token_endpoint_auth_method defaults to client_secret_basic
                tokenEndpointAuthMethod = OAuthTokenEndpointAuthMethod.ClientSecretBasic;
            }
            //
            // grant_types
            List<OAuthGrantType> grantTypes = new();
            var nullableGrantTypesAsStrings = request.grant_types;
            if (nullableGrantTypesAsStrings is not null)
            {
                foreach (var grantTypeAsString in nullableGrantTypesAsStrings!)
                {
                    var nullableGrantType = MorphicEnum<OAuthGrantType>.FromStringValue(grantTypeAsString);
                    if (nullableGrantType is null)
                    {
                        return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.UnknownGrantType(grantTypeAsString));
                    }
                    grantTypes.Add(nullableGrantType!.Value);
                }
            } 
            else
            {
                // if no grant types were provided, use the default
                // RFC 7591 Sec. 2: grant_types defaults to authorization_code
                grantTypes.Add(OAuthGrantType.AuthorizationCode);
            }
            //
            // response_types
            List<OAuthResponseType> responseTypes = new();
            var nullableResponseTypesAsStrings = request.response_types;
            if (nullableResponseTypesAsStrings is not null)
            {
                foreach (var responseTypeAsString in nullableResponseTypesAsStrings!)
                {
                    var nullableResponseType = MorphicEnum<OAuthResponseType>.FromStringValue(responseTypeAsString);
                    if (nullableResponseType is null)
                    {
                        return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.UnknownResponseType(responseTypeAsString));
                    }
                    responseTypes.Add(nullableResponseType!.Value);
                }
            } 
            else
            {
                // if no response types were provided, use the default
                // RFC 7591 Sec. 2: response_types defaults to code

                // NOTE: as some grant types do not have any corresponding required response type, we have chosen to only do this if the grant types list contains a grant type which requires a response type of code (and only if there were no requested response types)
                if (grantTypes.Contains(OAuthGrantType.AuthorizationCode))
                {
                    responseTypes.Add(OAuthResponseType.Code);
                }
            }
            //
            //// scope
            //List<string>? scopeAsStringList = new();
            //if (request.scope is not null)
            //{
            //    string[] scopeAsStringArray = request.scope.Split(' ');
            //    scopeAsStringList = new List<string>(scopeAsStringArray);
            //}
            //
            // software_id
            var softwareId = request.software_id;
            //
            // software_version
            var softwareVersion = request.software_version;

            // validate that the request metadata is a valid combination
            //
            // some grant_types must have matching (required) response_types
            // NOTE: OAuthClient.ValidateMetadata (directly and through OAuthClient.CreateAsync) also validates grantType->responseType pair requirements in the same manner; we may want to consider removing this check in the future and letting the model validation do this check
            if (grantTypes.Contains(OAuthGrantType.AuthorizationCode) == true)
            {
                if (responseTypes.Contains(OAuthResponseType.Code) == false)
                {
                    return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.GrantTypeRequiresMissingResponseType(OAuthGrantType.AuthorizationCode.ToStringValue()!, OAuthResponseType.Code.ToStringValue()!));
                }
            }
            if (grantTypes.Contains(OAuthGrantType.Implicit) == true)
            {
                if (responseTypes.Contains(OAuthResponseType.Token) == false)
                {
                    return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.GrantTypeRequiresMissingResponseType(OAuthGrantType.Implicit.ToStringValue()!, OAuthResponseType.Token.ToStringValue()!));
                }
            }
            //
            // grant types must have an allowed token endpoint auth method
            foreach (var grantType in grantTypes) {
                switch (grantType) {
                    case OAuthGrantType.AuthorizationCode:
                    case OAuthGrantType.Password:
                    case OAuthGrantType.ClientCredentials:
                    case OAuthGrantType.JwtBearer:
                    case OAuthGrantType.Saml2Bearer:
                        switch (tokenEndpointAuthMethod) {
                            case OAuthTokenEndpointAuthMethod.ClientSecretBasic:
                            case OAuthTokenEndpointAuthMethod.ClientSecretPost:
                                // allowed
                                break;
                            case OAuthTokenEndpointAuthMethod.None:
                                // disallowed
                                return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.GrantTypeAndTokenEndpointAuthMethodAreIncompatible(grantType.ToStringValue()!, tokenEndpointAuthMethod.ToStringValue()!));
                            default:
                                throw new MorphicUnhandledErrorException();
                        }
                        break;
                    case OAuthGrantType.Implicit:
                        switch (tokenEndpointAuthMethod) {
                            case OAuthTokenEndpointAuthMethod.None:
                                // allowed
                                break;
                            case OAuthTokenEndpointAuthMethod.ClientSecretBasic:
                            case OAuthTokenEndpointAuthMethod.ClientSecretPost:
                                // disallowed
                                return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.GrantTypeAndTokenEndpointAuthMethodAreIncompatible(grantType.ToStringValue()!, tokenEndpointAuthMethod.ToStringValue()!));
                            default:
                                throw new MorphicUnhandledErrorException();
                        }
                        break;
                    case OAuthGrantType.RefreshToken:
                        // not applicable
                        break;
                    default:
                        throw new MorphicUnhandledErrorException();
                }
            }
            //
            // redirect_uris must be valid (both in formatting and also acceptable to our OAuth server)
            if (redirectUrisAsStrings is not null)
            {
                foreach (var redirectUriAsString in redirectUrisAsStrings)
                {
                    Uri redirectUri;
                    try
                    {
                        redirectUri = new Uri(redirectUriAsString);
                    }
                    catch
                    {
                        return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.InvalidRedirectUri(redirectUriAsString));
                    }

                    // the URI was parseable; now validate that it complies with our rules for acceptable redirect URIs
                    // NOTE: OAuthClient.ValidateMetadata (directly and through OAuthClient.CreateAsync) also validates redirectUris in the same manner; we may want to consider removing this check in the future and letting the model validation do this check
                    //
                    var redirectUriScheme = redirectUri.Scheme.ToLowerInvariant();
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
                                        return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.InvalidRedirectUri(redirectUriAsString));
                                }
                            }
                            break;
                        case "https":
                            // https scheme is allowed
                            break;
                        default:
                            // other schemes are not allowed in this implementation
                            return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.InvalidRedirectUri(redirectUriAsString));
                    }

                    if (redirectUri.Fragment.Length > 0)
                    {
                        // fragment components are not allowed in redirect URIs
                        return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.InvalidRedirectUri(redirectUriAsString));
                    }
                }
            }
            //
            // if the grant types include redirection, at least one redirect uri must be supplied
            if (redirectUrisAsStrings is null || redirectUrisAsStrings.Count == 0) {
                foreach (OAuthGrantType grantType in grantTypes) {
                    switch (grantType) {
                        case OAuthGrantType.AuthorizationCode:
                        case OAuthGrantType.Implicit:
                            // supplied grant type required redirect uris, but none were provided
                            return MorphicResult.ErrorResult(ParseAndValidateClientRegistrationRequestContentError.GrantTypeRequiresRedirectUris(grantType.ToStringValue()!));
                        case OAuthGrantType.Password:
                        case OAuthGrantType.ClientCredentials:
                        case OAuthGrantType.RefreshToken:
                        case OAuthGrantType.JwtBearer:
                        case OAuthGrantType.Saml2Bearer:
                            break;
                        default:
                            throw new MorphicUnhandledErrorException();
                    }
                }
            }

            // create a client metadata instance using the accepted values
            var result = new OAuthClientMetadata()
            {
                RedirectUris = redirectUrisAsStrings,
                TokenEndpointAuthMethod = tokenEndpointAuthMethod,
                GrantTypes = grantTypes,
                ResponseTypes = responseTypes,
                SoftwareId = softwareId,
                SoftwareVersion = softwareVersion,
            };
            return MorphicResult.OkResult(result);
        }
    }
}