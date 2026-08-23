# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /source

COPY global.json ./
COPY src/KubeMcp/KubeMcp.csproj src/KubeMcp/
RUN dotnet restore src/KubeMcp/KubeMcp.csproj

COPY src/KubeMcp/ src/KubeMcp/
RUN dotnet publish src/KubeMcp/KubeMcp.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

COPY --from=build /app/publish ./

USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "KubeMcp.dll"]
