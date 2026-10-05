# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# The Dockerfile frontend and base images are pinned by verified multi-arch
# index digests (tags are kept for readability) so a rebuilt image cannot
# silently change its parser, SDK, or runtime. The .NET images are both pinned
# to explicit .NET 10 SDK/runtime versions so local, CI, and image builds stay
# aligned. global.json's "latestPatch" roll-forward remains within SDK feature
# band 4. The runtime image is 10.0.12 with patched OpenSSL packages; the
# SDK image is 10.0.401 and is only used for building, never shipped. The
# digests are the multi-arch manifest-list
# digests published by MCR; the build resolves the linux/amd64 variant. Update
# them (and the NuGet lock file) via Dependabot rather than editing tags by hand.
#   sdk:10.0.401  @ sha256:35d40304542c8689331f8cab17c65926cdf48fe711e289321d71924b230a7d29
#   aspnet:10.0.12 @ sha256:57460add89e2b3dd1950c41d8b7dc96eeb7a24d13d98e3656ce9997a8b746bd6
FROM mcr.microsoft.com/dotnet/sdk:10.0.401@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317 AS build
WORKDIR /source

# Restore is locked to the checked-in NuGet lock file (packages.lock.json) so a
# drifted dependency set fails the image build instead of resolving new
# versions. The lock file is copied before restore for this reason.
COPY global.json ./
COPY src/KubeMcp/KubeMcp.csproj src/KubeMcp/
COPY src/KubeMcp/packages.lock.json src/KubeMcp/
RUN dotnet restore --locked-mode src/KubeMcp/KubeMcp.csproj

COPY src/KubeMcp/ src/KubeMcp/
RUN dotnet publish src/KubeMcp/KubeMcp.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0.12@sha256:57460add89e2b3dd1950c41d8b7dc96eeb7a24d13d98e3656ce9997a8b746bd6 AS runtime
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

COPY --from=build /app/publish ./

USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "KubeMcp.dll"]
