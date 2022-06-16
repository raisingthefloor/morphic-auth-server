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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MigrateUsers.Morphic.Server.Core;

internal class BitConversionUtils
{
    internal static byte[] GetBytesBE(uint value)
    {
        var result = new byte[]
        {
            (byte)((value & 0xFF000000) >> 24),
            (byte)((value & 0x00FF0000) >> 16),
            (byte)((value & 0x0000FF00) >> 8),
            (byte)((value & 0x000000FF) >> 0),
        };

        return result;
    }

    internal static byte[] GetBytesBE(ushort value)
    {
        var result = new byte[]
        {
            (byte)((value & 0xFF00) >> 8),
            (byte)((value & 0x00FF) >> 0),
        };

        return result;
    }

    internal static uint FromBytesBE_UInt32(byte[] bytes)
    {
        if (bytes.Length != 4)
        {
            throw new ArgumentException("Argument '" + nameof(bytes) + "' has an unsupported length.");
        }

        var result =
            (((uint)bytes[0]) << 24) |
            (((uint)bytes[1]) << 16) |
            (((uint)bytes[2]) << 8) |
            (((uint)bytes[3]) << 0);
        
        return result;
    }

    internal static ushort FromBytesBE_UInt16(byte[] bytes)
    {
        if (bytes.Length != 2)
        {
            throw new ArgumentException("Argument '" + nameof(bytes) + "' has an unsupported length.");
        }

        // NOTE: C# does not support bitshifting on ushorts (i.e. UInt16s), so we create the result as a UInt32 before truncating the (all-zero) top 16 bits.
        var resultAsUInt32 =
            (((uint)bytes[0]) << 8) |
            (((uint)bytes[1]) << 0);
        var result = (ushort)resultAsUInt32;

        return result;
    }
}
