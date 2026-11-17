# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
#
# The Dockerfile frontend and base images are pinned by verified multi-arch
# index digests (tags are kept for readability) so a rebuilt image cannot
# silently change its parser, SDK, or runtime. The .NET images are pinned to
# explicit SDK/runtime versions so local, CI, and image builds stay aligned.
# global.json's "latestPatch" roll-forward remains within SDK feature band 4.
# The SDK image is only used for building, never shipped. The digests are the
# multi-arch manifest-list digests published by MCR; the build resolves the
# linux/amd64 variant. Update them (and the NuGet lock file) via Dependabot
# rather than editing tags by hand.
FROM mcr.microsoft.com/dotnet/sdk:10.0.404@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb AS build
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

FROM mcr.microsoft.com/dotnet/aspnet:10.0.15@sha256:bfd912c83295ce66d4b706ebb8541b9f14259b0e76fbb88b2751f58ce2399d2e AS runtime
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

COPY --from=build /app/publish ./

USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "KubeMcp.dll"]
