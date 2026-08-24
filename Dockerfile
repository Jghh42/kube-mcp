# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# The Dockerfile frontend and base images are pinned by verified multi-arch
# index digests (tags are kept for readability) so a rebuilt image cannot
# silently change its parser, SDK, or runtime. The .NET images are both pinned
# to .NET 10.0 feature band 1 so they agree with global.json's
# "latestPatch" roll-forward (no feature-band drift between local, CI and the
# image). The runtime image is the latest band-1 patch (10.0.11) so it ships
# current security fixes; the SDK image is the band-1 GA (10.0.100) and is only
# used for building, never shipped. The digests are the multi-arch manifest-list
# digests published by MCR; the build resolves the linux/amd64 variant. Update
# them (and the NuGet lock file) via Dependabot rather than editing tags by hand.
#   sdk:10.0.100  @ sha256:c7445f141c04f1a6b454181bd098dcfa606c61ba0bd213d0a702489e5bd4cd71
#   aspnet:10.0.11 @ sha256:a4556ed033fa96f984bb7a8d348851cb2d36b1281dd2420070045f664fbb5f94
FROM mcr.microsoft.com/dotnet/sdk:10.0.400@sha256:e1ffd2a92ae84c1291bc1b6887501f8af98e6331e7af6d4c8d37168c5e87a64c AS build
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

FROM mcr.microsoft.com/dotnet/aspnet:10.0.11@sha256:a4556ed033fa96f984bb7a8d348851cb2d36b1281dd2420070045f664fbb5f94 AS runtime
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

COPY --from=build /app/publish ./

USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "KubeMcp.dll"]
