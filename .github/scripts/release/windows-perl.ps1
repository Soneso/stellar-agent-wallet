# Points the vendored OpenSSL build at a Windows-native Perl. openssl-src runs
# OpenSSL's perl-based Configure, which needs a Perl with its full module set,
# and the MSYS perl that Git for Windows puts on PATH lacks it. openssl-src
# honors OPENSSL_SRC_PERL, so this script writes the path of Strawberry Perl
# to $env:GITHUB_ENV. The runner image carries Strawberry Perl; the script
# installs it when an image does not.
#
# check-workflow-invariants.py requires the body below to equal, line for
# line, the run block of the release build job's step that writes
# OPENSSL_SRC_PERL.
if (-not (Test-Path 'C:\Strawberry\perl\bin\perl.exe')) {
  choco install strawberryperl --no-progress -y
}
if (-not (Test-Path 'C:\Strawberry\perl\bin\perl.exe')) {
  Write-Error 'Strawberry Perl unavailable'
  exit 1
}
Add-Content $env:GITHUB_ENV "OPENSSL_SRC_PERL=C:\Strawberry\perl\bin\perl.exe"
