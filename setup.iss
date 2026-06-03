[Setup]
AppName=Interlude Defender
AppVersion=0.0.1
DefaultDirName={pf}\Interlude Defender
DefaultGroupName=Interlude Defender
OutputDir=Output
OutputBaseFilename=InterludeDefender_Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startup"; Description: "Launch Interlude Defender automatically on Windows startup (Recommended)"; GroupDescription: "Startup Options:"
Name: "scan_context"; Description: "Add 'Scan with Interlude Defender' to right-click context menu"; GroupDescription: "Explorer Integration:"

[Files]
Source: "dist\InterludeDefender\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Interlude Defender"; Filename: "{app}\InterludeDefender.exe"
Name: "{group}\Uninstall Interlude Defender"; Filename: "{uninstallexe}"
Name: "{commondesktop}\Interlude Defender"; Filename: "{app}\InterludeDefender.exe"; Tasks: desktopicon
Name: "{commonstartup}\Interlude Defender"; Filename: "{app}\InterludeDefender.exe"; Parameters: "--background"; Tasks: startup

[Registry]
; Context menu integration
Root: HKCR; Subkey: "Directory\shell\InterludeDefender"; ValueType: string; ValueData: "Scan with Interlude Defender"; Flags: uninsdeletekey; Tasks: scan_context
Root: HKCR; Subkey: "Directory\shell\InterludeDefender\command"; ValueType: string; ValueData: """{app}\InterludeDefender.exe"" --scan-path ""%1"""; Flags: uninsdeletekey; Tasks: scan_context

Root: HKCR; Subkey: "*\shell\InterludeDefender"; ValueType: string; ValueData: "Scan with Interlude Defender"; Flags: uninsdeletekey; Tasks: scan_context
Root: HKCR; Subkey: "*\shell\InterludeDefender\command"; ValueType: string; ValueData: """{app}\InterludeDefender.exe"" --scan-path ""%1"""; Flags: uninsdeletekey; Tasks: scan_context

[Run]
Filename: "{app}\InterludeDefender.exe"; Description: "{cm:LaunchProgram,Interlude Defender}"; Flags: nowait postinstall skipifsilent
