FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build-env
WORKDIR /app

COPY . ./

RUN dotnet restore
# RUN dotnet publish -c Release -o out
RUN dotnet publish -c Debug -o out

# Build runtime image
FROM mcr.microsoft.com/dotnet/core/aspnet:3.1
WORKDIR /app
COPY --from=build-env /app/out .
COPY entrypoint.sh .
EXPOSE 80
CMD ["/bin/sh", "/app/entrypoint.sh"]
