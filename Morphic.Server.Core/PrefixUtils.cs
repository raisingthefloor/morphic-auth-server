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

namespace Morphic.Server.Core 
{
    public class PrefixUtils
    {
        public static (string?, string) SplitPrefixAndValue(string prefixWithValue) 
        {
            string? prefix;
            string value;

            var prefixLength = prefixWithValue.LastIndexOf('-');
            if (prefixLength >= 0)
            {
                prefix = prefixWithValue.Substring(0, prefixLength);
                value = prefixWithValue.Substring(prefixLength + 1);
            }
            else
            {
                prefix = null;
                value = prefixWithValue;
            }

            return (prefix, value);
        }

        public static string CombinePrefixAndValue(string? prefix, string value)
        {
            if (prefix is not null)
            {
                return prefix! + "-" + value;
            }
            else
            {
                return value;
            }
        }
    }
}