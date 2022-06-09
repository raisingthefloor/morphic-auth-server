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

using System;
using System.Text;

namespace Morphic.Server.Core
{
    public struct Base64Utils 
    {

        // change any control characters and other urlencode-reserved characters into urlencode-unreserved characters
        // NOTE: per Google, the following four characters are _unreserved_ in URLs (in addition to all letters and numbers): '-'; '_'; '.'; '~'
        //      [we choose to use the latter three so that we can reserve the hyphen for our own use (such as prepending region ids)]
        // see: https://developers.google.com/maps/url-encoding
        public static string ConvertBase64StringToUrlBase64String(string base64String)
        {
            var stringBuilder = new StringBuilder();
            for (var index = 0; index < base64String.Length; index += 1)
            {
                var ch = base64String[index] switch 
                {
                    var x when x >= '0' && x <= '9' => x,
                    var x when x >= 'a' && x <= 'z' => x,
                    var x when x >= 'A' && x <= 'Z' => x,
                    '+' => '_',
                    '/' => '.',
                    '=' => '~',
                    _ => throw new ArgumentException("Argument 'base64String' contains characters which do not exist in base 64 strings"),
                };
                stringBuilder.Append(ch);
            }

            return stringBuilder.ToString();
        }

        // change any control characters and other urlencode-reserved characters into urlencode-unreserved characters
        // NOTE: per Google, the following four characters are _unreserved_ in URLs (in addition to all letters and numbers): '-'; '_'; '.'; '~'
        //      [we choose to use the latter three so that we can reserve the hyphen for our own use (such as prepending region ids)]
        // see: https://developers.google.com/maps/url-encoding
        public static string ConvertUrlBase64StringToBase64String(string urlEncodeSafeBase64String)
        {
            var stringBuilder = new StringBuilder();
            for (var index = 0; index < urlEncodeSafeBase64String.Length; index += 1)
            {
                var ch = urlEncodeSafeBase64String[index] switch
                {
                    var x when x >= '0' && x <= '9' => x,
                    var x when x >= 'a' && x <= 'z' => x,
                    var x when x >= 'A' && x <= 'Z' => x,
                    '_' => '+',
                    '.' => '/',
                    '~' => '=',
                    _ => throw new ArgumentException("Argument 'base64String' contains characters which do not exist in URLencode-safe base 64 strings"),
                };
                stringBuilder.Append(ch);
            }

            return stringBuilder.ToString();
        }

    }
}