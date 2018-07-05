FROM microsoft/aspnetcore-build:1.1 AS build-env
COPY ./MiraclAuthentication.Core1.1 ./MiraclAuthentication.Core1.1
COPY ./demo ./demo
WORKDIR /demo
RUN dotnet restore --verbosity quiet
RUN dotnet publish -c Release -o out

FROM microsoft/aspnetcore:1.1
WORKDIR /demo
COPY --from=build-env /demo/out .
ENTRYPOINT ["dotnet", "demo.dll"]
