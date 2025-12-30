# Copyright 2022-2025 Raising the Floor - US, Inc.
#
# Licensed under the New BSD license. You may not use this file except in
# compliance with this License.
#
# You may obtain a copy of the License at
# https://github.com/raisingthefloor/morphic-auth-server/blob/master/LICENSE.txt
#
# The R&D leading to these results received funding from the:
# * Rehabilitation Services Administration, US Dept. of Education under
#   grant H421A150006 (APCP)
# * National Institute on Disability, Independent Living, and
#   Rehabilitation Research (NIDILRR)
# * Administration for Independent Living & Dept. of Education under grants
#   H133E080022 (RERC-IT) and H133E130028/90RE5003-01-00 (UIITA-RERC)
# * European Union's Seventh Framework Programme (FP7/2007-2013) grant
#   agreement nos. 289016 (Cloud4all) and 610510 (Prosperity4All)
# * William and Flora Hewlett Foundation
# * Ontario Ministry of Research and Innovation
# * Canadian Foundation for Innovation
# * Adobe Foundation
# * Consumer Electronics Association Foundation

#see: https://github.com/dotnet/dotnet-docker/blob/main/README.sdk.md & https://mcr.microsoft.com/artifact/mar/dotnet/sdk/tags
ARG SDK_VERSION=10.0.101-alpine3.23
#
#see: https://github.com/dotnet/dotnet-docker/blob/main/README.aspnet.md & https://mcr.microsoft.com/artifact/mar/dotnet/aspnet/tags
ARG ASPNET_VERSION=10.0.1-alpine3.23

FROM mcr.microsoft.com/dotnet/aspnet:${ASPNET_VERSION} AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:${SDK_VERSION} AS build
WORKDIR /src
COPY ["MorphicAuthServer.csproj", "."]
RUN dotnet restore "./MorphicAuthServer.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "MorphicAuthServer.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "MorphicAuthServer.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MorphicAuthServer.dll"]