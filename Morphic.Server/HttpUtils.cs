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

namespace Morphic.Server;

using Morphic.Core;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Globalization;
using System.IO;

internal struct HttpUtils
{
    public static readonly System.Text.Encoding DefaultHttpEncoding = System.Text.Encoding.GetEncoding("iso-8859-1");

    public enum HttpContentType
    {
        Json,
        WwwFormUrlencoded
    }

    public enum HttpResponseCode : int
    {
        HTTP_200_OK = 200,
        HTTP_201_CREATED = 201,
        // HTTP_204_NO_CONTENT = 204,
        // HTTP_302_FOUND = 302,
        // HTTP_307_TEMPORARY_REDIRECT = 307,
        // HTTP_308_PERMANENT_REDIRECT = 308,
        HTTP_400_BAD_REQUEST = 400,
        HTTP_401_UNAUTHORIZED = 401,
        HTTP_403_FORBIDDEN = 403,
        // HTTP_404_NOT_FOUND = 404,
        // HTTP_405_METHOD_NOT_ALLOWED = 405,
        HTTP_406_NOT_ACCEPTABLE = 406,
        // HTTP_410_GONE = 410,
        // HTTP_413_PAYLOAD_TOO_LARGE = 413,
        HTTP_415_UNSUPPORTED_MEDIA_TYPE = 415,
        HTTP_500_INTERNAL_SERVER_ERROR = 500,
    }

    public struct HttpErrorResponse
    {
        public HttpResponseCode StatusCode;
        public string? ContentType;
        public string Content;

        public HttpErrorResponse(HttpResponseCode statusCode, string? contentType, string content)
        {
            this.StatusCode = statusCode;
            this.ContentType = contentType;
            this.Content = content;
        }

        public static HttpErrorResponse InternalServerErrorResponse
        {
            get
            {
                return new HttpErrorResponse(HttpResponseCode.HTTP_500_INTERNAL_SERVER_ERROR, null, String.Empty);
            }
        }
    }

    public record VerifyContentTypeHeaderError : MorphicAssociatedValueEnum<VerifyContentTypeHeaderError.Values>
    {
        // enum members
        public enum Values
        {
            InvalidContentType,
            NoSupportedEncodings,
            ContentTypeUnsupported,
            CharsetUnsupportedForContentType,
        }

        //

        // functions to create member instances
        //
        public static VerifyContentTypeHeaderError CharsetUnsupportedForContentType
        {
            get
            {
                var httpErrorResponse = new HttpErrorResponse(
                    HttpResponseCode.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    "text/plain",
                    "ERROR: Charset encoding is not supported for this Content-Type.");
                return new VerifyContentTypeHeaderError(Values.CharsetUnsupportedForContentType) { HttpResponse = httpErrorResponse };
            }
        }
        public static VerifyContentTypeHeaderError ContentTypeUnsupported(string requiredContentTypeAsString)
        {
            var httpErrorResponse = new HttpErrorResponse(
                HttpResponseCode.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                "text/plain",
                "ERROR: Content-Type must be '" + requiredContentTypeAsString + "'.");
            return new VerifyContentTypeHeaderError(Values.ContentTypeUnsupported) { HttpResponse = httpErrorResponse };
        }
        public static VerifyContentTypeHeaderError InvalidContentType
        {
            get
            {
                return new VerifyContentTypeHeaderError(Values.InvalidContentType);
            }
        }
        public static VerifyContentTypeHeaderError NoSupportedEncodings
        {
            get
            {
                return new VerifyContentTypeHeaderError(Values.NoSupportedEncodings);
            }
        }

        // associated values
        public HttpErrorResponse? HttpResponse;

        // verbatim required constructor implementation for MorphicAssociatedValueEnums
        private VerifyContentTypeHeaderError(Values value) : base(value) { }
    }
    
    public static MorphicResult<MorphicUnit, VerifyContentTypeHeaderError> VerifyContentTypeHeaderIsJson(HttpContext context)
    {
        // NOTE: we currently only supported UTF8 encoding for JSON; if other options are supported in the future, consider returning the charset instead of bool
        return HttpUtils.VerifyContentTypeHeader(context, HttpContentType.Json, new List<System.Text.Encoding>() { System.Text.Encoding.UTF8 });
    }

    public static MorphicResult<MorphicUnit, VerifyContentTypeHeaderError> VerifyContentTypeHeaderIsWwwFormUrlEncodedAsync(HttpContext context)
    {
        return VerifyContentTypeHeader(context, HttpContentType.WwwFormUrlencoded, new List<System.Text.Encoding>() { System.Text.Encoding.UTF8 });
    }

    public static MorphicResult<MorphicUnit, VerifyContentTypeHeaderError> VerifyContentTypeHeader(HttpContext context, HttpContentType requiredContentType, List<System.Text.Encoding>? supportedEncodings = null)
    {
        // validate the requiredContentType argument
        string? requiredContentTypeAsString = HttpUtils.ConvertHttpContentTypeToString(requiredContentType);
        if (requiredContentTypeAsString is null)
        {
            return MorphicResult.ErrorResult(VerifyContentTypeHeaderError.InvalidContentType);
        }
        //
        if (supportedEncodings is null)
        {
            // if supportedEncodings is null, determine the default encoding based on the content type
            supportedEncodings = new List<System.Text.Encoding>() { HttpUtils.GetDefaultEncodingForHttpContentType(requiredContentType) };
        }
        else if (supportedEncodings.Count == 0)
        {
            // if supportedEncodings is an empty (non-null) list, we cannot match the encoding; return error.
            return MorphicResult.ErrorResult(VerifyContentTypeHeaderError.NoSupportedEncodings);
        }

        // verify that the content-type header matches the required type
        var contentTypeResults = HttpUtils.ParseContentTypeHeader(context.Request.ContentType);
        string? contentType = contentTypeResults.ContentType;
        if (contentType != requiredContentTypeAsString)
        {
            return MorphicResult.ErrorResult(VerifyContentTypeHeaderError.ContentTypeUnsupported(requiredContentTypeAsString));
        }

        // verify the charset (encoding)
        if (HttpUtils.VerifyContentEncoding(supportedEncodings, contentTypeResults.ExplicitEncoding, contentTypeResults.DefaultEncoding).IsError == true)
        {
            return MorphicResult.ErrorResult(VerifyContentTypeHeaderError.CharsetUnsupportedForContentType);
        }

        return MorphicResult.OkResult();
    }

    //

    public record VerifyAcceptHeaderError : MorphicAssociatedValueEnum<VerifyAcceptHeaderError.Values>
    {
        // enum members
        public enum Values
        {
            ContentTypeUnsupported,
        }

        // functions to create member instances
        //
        public static VerifyAcceptHeaderError ContentTypeUnsupported(string requiredContentTypeAsString)
        {
            var httpErrorResponse = new HttpErrorResponse(
                HttpResponseCode.HTTP_406_NOT_ACCEPTABLE,
                "text/plain",
                "ERROR: Accept header must equal '" + requiredContentTypeAsString + "'.");
            return new VerifyAcceptHeaderError(Values.ContentTypeUnsupported) { HttpResponse = httpErrorResponse };
        }

        // associated values
        public HttpErrorResponse? HttpResponse;

        // verbatim required constructor implementation for MorphicAssociatedValueEnums
        private VerifyAcceptHeaderError(Values value) : base(value) { }
    }
    
    public static MorphicResult<MorphicUnit, VerifyAcceptHeaderError> VerifyAcceptHeaderIsJson(HttpContext context)
    {
        return VerifyAcceptHeader(context, HttpContentTypeAsString.Json);
    }
    
    public static MorphicResult<MorphicUnit, VerifyAcceptHeaderError> VerifyAcceptHeader(HttpContext context, string requiredContentType)
    {
        // verify that the accept header is valid
        var acceptContentTypes = (ICollection<String>)context.Request.Headers["Accept"];
        if (acceptContentTypes.Contains(requiredContentType) == false)
        {
            return MorphicResult.ErrorResult(VerifyAcceptHeaderError.ContentTypeUnsupported(requiredContentType));
        }

        return MorphicResult.OkResult();
    }

    //

    public struct ParseContentTypeHeaderResult
    {
        public string? ContentType { get; }
        public System.Text.Encoding? ExplicitEncoding { get; }
        public System.Text.Encoding DefaultEncoding { get; }

        public ParseContentTypeHeaderResult(string? contentType, System.Text.Encoding? explicitEncoding, System.Text.Encoding defaultEncoding)
        {
            this.ContentType = contentType;
            this.ExplicitEncoding = explicitEncoding;
            this.DefaultEncoding = defaultEncoding;
        }
    }
    // NOTE: this function returns the parsed content-type, the parsed encoding, and the default encoding for the parsed content-type
    //       if no content-type was specified, then the content-type is assumed to be application/octet-stream.
    public static ParseContentTypeHeaderResult ParseContentTypeHeader(string? headerValue)
    {
        string CHARSET_QUERY_NAME = "charset";
        string? contentType = null;
        System.Text.Encoding? explicitContentEncoding = null;
        System.Text.Encoding? defaultContentEncoding = null;
        bool mustIgnoreExplicitEncoding = false;

        if (headerValue is null)
        {
            // NOTE: all HTTP/1.1 requests with bodies SHOULD include the Content-Type header; if it is missing we should assume application/octet-stream.
            contentType = "application/octet-stream";
            defaultContentEncoding = HttpUtils.DefaultHttpEncoding;
        }
        else if (headerValue == string.Empty)
        {
            // if the content-type header is empty, assume the default HTTP encoding
            defaultContentEncoding = HttpUtils.DefaultHttpEncoding;
        }
        else
        {
            string[] contentTypeElements = headerValue.Split(';');
            // NOTE: the first element _must_ be the content type
            contentType = contentTypeElements[0];

            // determine the default encoding
            switch (contentType.ToLowerInvariant())
            {
                case HttpContentTypeAsString.Json:
                    // application/json uses UTF8 by default
                    defaultContentEncoding = System.Text.Encoding.UTF8;
                    /* NOTE: we are assuming that this type cannot have an explictly-provided charset and that the charset must be inferred as UTF-8. */
                    mustIgnoreExplicitEncoding = true;
                    break;
                case HttpContentTypeAsString.WwwFormUrlencoded:
                    // application/x-www-form-urlencoded uses UTF8 exclusively and does not support the optional charset argument
                    defaultContentEncoding = System.Text.Encoding.UTF8;
                    mustIgnoreExplicitEncoding = true;
                    break;
                default:
                    // for all other encodings, assume the default HTTP encoding
                    defaultContentEncoding = HttpUtils.DefaultHttpEncoding;
                    break;
            }

            if (mustIgnoreExplicitEncoding == false)
            {
                // now parse the remaining elements to find the explicitly-defined encoding, if one is supplied.
                for (int iElement = 1; iElement < contentTypeElements.Length; iElement++)
                {
                    var element = contentTypeElements[iElement].ToLowerInvariant().Trim();
                    if (element.Substring(0, CHARSET_QUERY_NAME.Length + 1) == CHARSET_QUERY_NAME + "=")
                    {
                        switch (element.Substring(CHARSET_QUERY_NAME.Length + 1))
                        {
                            case "utf-8":
                                explicitContentEncoding = System.Text.Encoding.UTF8;
                                break;
                            case "iso-8859-1":
                                explicitContentEncoding = System.Text.Encoding.GetEncoding("iso-8859-1");
                                break;
                            default:
                                // unknown encoding
                                break;
                        }
                    }
                }
            }
        }

        return new ParseContentTypeHeaderResult(contentType, explicitContentEncoding, defaultContentEncoding);
    }

    private struct HttpContentTypeAsString
    {
        public const string Json = "application/json";
        public const string WwwFormUrlencoded = "application/x-www-form-urlencoded";
    }

    private static string? ConvertHttpContentTypeToString(HttpContentType contentType)
    {
        switch (contentType)
        {
            case HttpContentType.Json:
                return HttpContentTypeAsString.Json;
            case HttpContentType.WwwFormUrlencoded:
                return HttpContentTypeAsString.WwwFormUrlencoded;
            default:
                return null;
        }
    }

    //

    private static System.Text.Encoding GetDefaultEncodingForHttpContentType(HttpContentType contentType)
    {
        switch (contentType)
        {
            case HttpContentType.Json:
                return System.Text.Encoding.UTF8;
            case HttpContentType.WwwFormUrlencoded:
                return HttpUtils.DefaultHttpEncoding;
            default:
                return HttpUtils.DefaultHttpEncoding;
        }
    }

    //

    private static MorphicResult<MorphicUnit, MorphicUnit> VerifyContentEncoding(System.Text.Encoding supportedEncoding, System.Text.Encoding? explicitEncoding, System.Text.Encoding defaultEncoding)
    {
        return VerifyContentEncoding(new List<System.Text.Encoding>() { supportedEncoding }, explicitEncoding, defaultEncoding);
    }

    private static MorphicResult<MorphicUnit, MorphicUnit> VerifyContentEncoding(List<System.Text.Encoding> supportedEncodings, System.Text.Encoding? explicitEncoding, System.Text.Encoding defaultEncoding)
    {
        foreach (System.Text.Encoding supportedEncoding in supportedEncodings)
        {
            if ((supportedEncoding == explicitEncoding) || (explicitEncoding is null && supportedEncoding == defaultEncoding))
            {
                return MorphicResult.OkResult();
            }
        }
        // no match found
        return MorphicResult.ErrorResult();
    }

    //

    public static void SetHttpResponseStatusToOk(HttpContext context)
    {
        context.Response.StatusCode = (int)HttpResponseCode.HTTP_200_OK;
    }

    //

    public static async Task WriteHttpErrorResponseAsync(HttpContext context, HttpErrorResponse httpErrorResponse)
    {
        context.Response.StatusCode = (int)httpErrorResponse.StatusCode;
        if (httpErrorResponse.ContentType is not null) 
        {
            context.Response.ContentType = httpErrorResponse.ContentType;
            await context.Response.WriteAsync(httpErrorResponse.Content);
        }
        else
        {
            await context.Response.WriteAsync(String.Empty);
        }
    }

    //

    public static async Task WriteHttpBadRequestJsonErrorResponseAsync(HttpContext context, string errorJson)
    {
        var httpErrorResponse = new HttpUtils.HttpErrorResponse(
            HttpUtils.HttpResponseCode.HTTP_400_BAD_REQUEST,
            HttpContentTypeAsString.Json,
            errorJson);
        await HttpUtils.WriteHttpErrorResponseAsync(context, httpErrorResponse);
    }

    public static async Task WriteHttpBadRequestErrorResponseAsync(HttpContext context, string? errorText = null)
    {
        var httpErrorResponse = new HttpUtils.HttpErrorResponse(
            HttpUtils.HttpResponseCode.HTTP_400_BAD_REQUEST,
            errorText != null ? "text/plain" : null,
            errorText ?? string.Empty);
        await HttpUtils.WriteHttpErrorResponseAsync(context, httpErrorResponse);
    }

    //

    public static void SetHttpResponseStatusToUnauthorized(HttpContext context, string wwwAuthenticateHeader = "Bearer")
    {
        context.Response.StatusCode = (int)HttpResponseCode.HTTP_401_UNAUTHORIZED;
        context.Response.Headers["WWW-Authenticate"] = wwwAuthenticateHeader;
    }

    //

    public static string? ExtractBearerTokenFromAuthorizationHeaderValue(HttpContext context)
    {
        return ExtractBearerTokenFromHeaderValue(context.Request.Headers["Authorization"]);
    }

    public static string? ExtractBearerTokenFromHeaderValue(Microsoft.Extensions.Primitives.StringValues headerValues)
    {
        const string BEARER_PREFIX_LOWERCASE = "bearer ";

        if (
            (headerValues.Count > 0) &&
            (headerValues[0].Length >= BEARER_PREFIX_LOWERCASE.Length) &&
            (headerValues[0].Substring(0, BEARER_PREFIX_LOWERCASE.Length).ToLowerInvariant() == BEARER_PREFIX_LOWERCASE)
        )
        {
            return headerValues[0].Substring(BEARER_PREFIX_LOWERCASE.Length);
        }
        else
        {
            return null;
        }
    }

    //

    public static void SetHttpResponseStatusToForbidden(HttpContext context)
    {
        context.Response.StatusCode = (int)HttpResponseCode.HTTP_403_FORBIDDEN;
    }

    //

    public static MorphicResult<string, MorphicUnit> ParseQueryParameterAsString(HttpContext context, string parameterName)
    {
        var parameterStringValues = context.Request.Query[parameterName];
        if (parameterStringValues.Count != 1)
        {
            return MorphicResult.ErrorResult();
        }

        return MorphicResult.OkResult(parameterStringValues[0]);
    }

    //

    public record ReadRequestBodyAsByteArrayError : MorphicAssociatedValueEnum<ReadRequestBodyAsByteArrayError.Values>
    {
        // enum members
        public enum Values
        {
            TooLarge,
        }

        // functions to create member instances
        public static ReadRequestBodyAsByteArrayError TooLarge(byte[] partialResult) => new ReadRequestBodyAsByteArrayError(Values.TooLarge) { PartialResult = partialResult };

        // associated values
        public byte[]? PartialResult;

        // verbatim required constructor implementation for MorphicAssociatedValueEnums
        private ReadRequestBodyAsByteArrayError(Values value) : base(value) { }
    }
    //
    public static async Task<MorphicResult<byte[], ReadRequestBodyAsByteArrayError>> ReadRequestBodyAsByteArrayAsync(HttpContext context, int? maximumSize = null)
    {
        var resultAsStream = new MemoryStream();

        int position = 0;

        var buffer = new byte[65536];
        while (true)
        {
            var numberOfBytesRead = await context.Request.Body.ReadAsync(buffer, 0, buffer.Length);
            if (numberOfBytesRead == 0)
            {
                break;
            }

            await resultAsStream.WriteAsync(buffer, position, numberOfBytesRead);
            position += numberOfBytesRead;

            if (maximumSize is not null && position > maximumSize)
            {
                // capture just the first "maximumSize" bytes of the result (to return to our caller with the error result)
                var tooLargeResult = resultAsStream.ToArray();
                var partialResult = new byte[maximumSize.Value];
                Array.Copy(tooLargeResult, partialResult, maximumSize.Value);

                return MorphicResult.ErrorResult(ReadRequestBodyAsByteArrayError.TooLarge(partialResult));
            }
        }

        return MorphicResult.OkResult(resultAsStream.ToArray());
    }

}
