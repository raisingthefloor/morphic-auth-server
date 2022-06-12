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

namespace MorphicAuthServer;

using System;

internal class AppSettings
{
    private static string? _regionId = null;

    // NOTE: as an optimization, we only load this value once; the server must be restarted to recognize an updated setting value
    public static string GetRegionId()
    {
        if (_regionId is null) 
        {
            var regionId = Morphic.Server.Settings.MorphicAppSetting.GetSetting("auth-server", "REGION_ID");
            if (regionId is null) { throw new Exception("Application secret auth-server/REGION_ID was not found."); }
            _regionId = regionId;
        }

        return _regionId;
    }
}
