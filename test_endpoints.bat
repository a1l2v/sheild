@echo off
setlocal enabledelayedexpansion

:: Edit BASE_URL if your server is running on a different host/port
set "BASE_URL=http://127.0.0.1:8000"

echo =================================================================
echo Running API smoke test (register -> login -> protected -> signout)
echo =================================================================

echo 1) Registering user 'alice'...
powershell -Command "try { $body = @{ username='alice'; password='wonderland'; full_name='Alice' } | ConvertTo-Json; $r = Invoke-RestMethod -Uri '%BASE_URL%/register' -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop; $r | ConvertTo-Json -Compress } catch { Write-Error $_; exit 1 }" > register_response.json
if errorlevel 1 (
  echo Register failed. See register_response.json
  type register_response.json
  goto :cleanup
)
echo Registered. Response saved to register_response.json

echo.
echo 2) Logging in to get session token...
powershell -Command "try { $body = @{ username='alice'; password='wonderland' } | ConvertTo-Json; $r = Invoke-RestMethod -Uri '%BASE_URL%/login' -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop; $r | ConvertTo-Json -Compress } catch { Write-Error $_; exit 1 }" > login_response.json
if errorlevel 1 (
  echo Login failed. See login_response.json
  type login_response.json
  goto :cleanup
)
echo Login response saved to login_response.json

echo Extracting session token...
for /f "usebackq delims=" %%a in (`powershell -Command "(Get-Content login_response.json | ConvertFrom-Json).session_token"`) do set "TOKEN=%%a"
if "%TOKEN%"=="" (
  echo Failed to extract token.
  type login_response.json
  goto :cleanup
)
echo Token: %TOKEN%

echo.
echo 3) Calling protected endpoint with session token...
powershell -Command "try { $h = @{ Authorization = 'Session %TOKEN%' }; $r = Invoke-RestMethod -Uri '%BASE_URL%/protected' -Headers $h -Method Get -ErrorAction Stop; $r | ConvertTo-Json -Compress } catch { Write-Error $_; exit 1 }" > protected_response.json
if errorlevel 1 (
  echo Protected endpoint failed. See protected_response.json
  type protected_response.json
  goto :cleanup
)
echo Protected response:
type protected_response.json

echo.
echo 4) Signing out...
powershell -Command "try { $h = @{ Authorization = 'Session %TOKEN%' }; $r = Invoke-RestMethod -Uri '%BASE_URL%/signout' -Headers $h -Method Post -ErrorAction Stop; $r | ConvertTo-Json -Compress } catch { Write-Error $_; exit 1 }" > signout_response.json
if errorlevel 1 (
  echo Signout failed. See signout_response.json
  type signout_response.json
  goto :cleanup
)
echo Signout response:
type signout_response.json

:cleanup
echo.
echo Test complete. JSON responses are in the current directory:
echo  - register_response.json
echo  - login_response.json
echo  - protected_response.json
echo  - signout_response.json
echo.
echo If you need to change the username/password or server address, edit this .bat and update BASE_URL or credentials near the top.
echo =================================================================
pause
endlocal
