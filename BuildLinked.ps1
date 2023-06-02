# Set Working Directory
Split-Path $MyInvocation.MyCommand.Path | Push-Location
[Environment]::CurrentDirectory = $PWD

Remove-Item "$env:RELOADEDIIMODS/nmskat/*" -Force -Recurse
dotnet publish "./nmskat.csproj" -c Release -o "$env:RELOADEDIIMODS/nmskat" /p:OutputPath="./bin/Release" /p:ReloadedILLink="true"

# Restore Working Directory
Pop-Location