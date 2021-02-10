// Copyright 2021 Raising the Floor - International
//
// Licensed under the New BSD license. You may not use this file except in
// compliance with this License.
//
// You may obtain a copy of the License at
// https://github.com/GPII/universal/blob/master/LICENSE.txt
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
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace MorphicAuthServer
{
    public class Startup
    {
        // public Startup(IConfiguration configuration)
        // {
        //     Configuration = configuration;
        // }

        // public IConfiguration Configuration { get; }

        // public void ConfigureServices(IServiceCollection services)
        // {

        // }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            // TODO: disable HTTP port (except perhaps as redirect to HTTPS port)
            // TODO: add routing/error handling which returns 404 for invalid routes
            // TODO: determine if we need to support HTTP HEAD requests

            app.UseEndpoints(endpoints =>
            {

                // endpoints.MapGet("/oauth2/token/{token_id}", async (context) =>
                // {
                //     var tokenId = context.Request.RouteValues["token_id"].ToString();
                //     await OAuth2ServiceEndpoints.GetTokenAsync(context, tokenId);
                // });
            });
        }
    }
}