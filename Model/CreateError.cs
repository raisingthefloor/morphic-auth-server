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

using Morphic.Core;
using System;

internal record CreateError : MorphicAssociatedValueEnum<CreateError.Values>
{
    // enum members
    public enum Values
    {
        CouldNotCreateUniqueId,
        CryptographyFailed,
        DatabaseFailure,
        ValidationFailed
    }

    // functions to create member instances
    public static CreateError CouldNotCreateUniqueId => new(Values.CouldNotCreateUniqueId);
    public static CreateError CryptographyFailed => new(Values.CryptographyFailed);
    public static CreateError DatabaseFailure(Exception exception) => new(Values.DatabaseFailure) { Exception = exception };
    public static CreateError ValidationFailed(object? validationError) => new(Values.ValidationFailed) { ValidationError = validationError };

    // associated values
    public Exception? Exception { get; private set; }
    public object? ValidationError { get; private set; }

    // verbatim required constructor implementation for MorphicAssociatedValueEnums
    private CreateError(Values value) : base(value) { }
}
