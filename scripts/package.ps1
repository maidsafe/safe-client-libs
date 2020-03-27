$cargo_script_path = $pwd.path + "\cargo-script.exe"
Remove-Item -Path .\target\deploy -Recurse -Force -ErrorAction SilentlyContinue
$url = "https://s3.eu-west-2.amazonaws.com/download-native-libs/cargo-script.exe"
Invoke-WebRequest $url -OutFile "cargo-script.exe"
New-Item -Path ".\target\deploy" -ItemType directory
$COMMIT_MESSAGE = "$env:APPVEYOR_REPO_COMMIT_MESSAGE $env:APPVEYOR_REPO_COMMIT_MESSAGE_EXTENDED"
if ($COMMIT_MESSAGE -match "[Vv]ersion change.*safe_authenticator_ffi to ([^;]+)") {
  & $cargo_script_path script -- .\scripts\package.rs --lib --name safe_authenticator_ffi -d target\deploy --mock --strip --rebuild
  & $cargo_script_path script -- .\scripts\package.rs --lib --name safe_authenticator_ffi -d target\deploy --strip --rebuild
} else {
  & $cargo_script_path script -- .\scripts\package.rs --lib --name safe_authenticator_ffi -d target\deploy --mock --commit --strip --rebuild
  & $cargo_script_path script -- .\scripts\package.rs --lib --name safe_authenticator_ffi -d target\deploy --commit --strip --rebuild
}
